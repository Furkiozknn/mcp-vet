"""mcp-vet's own attack surface.

The tool reads untrusted repositories and prints what it finds into a terminal
and into an AI agent's context window. That makes the analyzer itself a target,
and these are the properties that have to hold no matter what a repository
contains:

* No escape sequence in repository content survives into output. A crafted
  description could otherwise erase the findings above it or make a hostile URL
  render as `api.github.com`.
* Nothing from the repository is ever executed, imported or evaluated.
* Malformed, enormous or adversarial input degrades one section of the report
  instead of crashing the run - a scanner that dies on a hostile input is a
  scanner an attacker can switch off.
"""
from __future__ import annotations

import json
import os

import pytest

from mcp_vet import dependencies, network, source
from mcp_vet.audit import audit_directory
from mcp_vet.github import RepoMeta
from mcp_vet.report import render_search_table, render_text
from mcp_vet.scanning import ScannedFile, sanitize_text, scan_tree, snippet

from helpers import fixture, iso, repo_json


class TestTerminalEscapeNeutralisation:
    @pytest.mark.parametrize(
        "raw",
        [
            "\x1b[31mred\x1b[0m",
            "\x1b[2J\x1b[H",                                   # clear screen, home cursor
            "\x1b]8;;https://evil.example\x07github.com\x1b]8;;\x07",  # OSC-8 hyperlink
            "\x1b[1A\x1b[2K",                                   # move up, erase line
            "before\x07after",                                  # bell
            "a\x00b",                                           # NUL
            "\x1bc",                                            # full terminal reset
        ],
    )
    def test_escape_sequences_are_removed(self, raw):
        cleaned = sanitize_text(raw)
        assert "\x1b" not in cleaned
        assert "\x00" not in cleaned
        assert "\x07" not in cleaned

    @pytest.mark.parametrize("raw", ["if (x) {‮ // }‬", "a​b", "c⁦d⁩"])
    def test_bidi_and_invisible_characters_are_removed(self, raw):
        cleaned = sanitize_text(raw)
        for char in "‮‬​⁦⁩":
            assert char not in cleaned

    def test_tabs_and_newlines_survive(self):
        # Over-sanitising would mangle every code snippet in the report.
        assert sanitize_text("a\tb\nc") == "a\tb\nc"

    def test_repo_metadata_is_sanitized_on_the_way_in(self):
        meta = RepoMeta.from_github_json(
            repo_json(full_name="acme/\x1b[31mevil\x1b[0m",
                      description="\x1b]8;;http://evil\x07safe\x1b]8;;\x07")
        )
        assert "\x1b" not in meta.full_name
        assert "\x1b" not in (meta.description or "")

    def test_no_escape_survives_into_a_rendered_report(self):
        report = audit_directory(fixture("hostile_text"), target="acme/hostile")
        text = render_text(report, verbose=True)
        for bad in ("\x1b", "\x00", "\x07", "‮", "​"):
            assert bad not in text

    def test_report_emits_no_escape_sequences_of_its_own(self):
        # If mcp-vet coloured its output, a reader could not tell mcp-vet's
        # formatting from a repository's injected formatting.
        report = audit_directory(fixture("exfil_server"))
        assert "\x1b" not in render_text(report, verbose=True)


class TestBoundedWork:
    def test_a_very_long_line_does_not_blow_up_the_snippet(self):
        assert len(snippet("x" * 100_000, limit=200)) <= 200

    def test_enormous_readme_is_still_processed(self):
        report = audit_directory(fixture("hostile_text"))
        assert report.notes["files_scanned"] >= 1

    def test_oversized_files_are_reported_not_silently_dropped(self, tmp_path):
        # An attacker who knows the size limit would hide code past it, so the
        # limit has to be visible in the report.
        big = tmp_path / "huge.py"
        big.write_text("# pad\n" + ("x" * 600_000))
        result = scan_tree(str(tmp_path))
        assert [p for p, _ in result.skipped_too_large] == ["huge.py"]
        report = audit_directory(str(tmp_path))
        assert any("size limit" in lim for lim in report.limitations)

    def test_pathological_regex_input_finishes_quickly(self):
        import time

        text = ("curl " * 400) + ("a" * 20_000) + " | "
        scanned = ScannedFile(path="x.sh", text=text, lines=[text], size_bytes=len(text))
        start = time.time()
        source.scan_matches([scanned])
        assert time.time() - start < 2.0


class TestMalformedInput:
    def test_malformed_json_manifest_degrades_one_section(self):
        result = scan_tree(fixture("hostile_text"))
        report = dependencies.analyze(result)
        # Status says the data could not be read; it must not read as "clean".
        assert report.status.value == "UNAVAILABLE"
        assert any("not valid JSON" in note for note in report.notes)

    def test_a_broken_manifest_does_not_abort_the_audit(self):
        report = audit_directory(fixture("hostile_text"))
        assert report.overall is not None
        assert report.recommendation

    def test_malformed_timestamp_raises_a_typed_error_not_a_crash(self):
        from mcp_vet.popularity import parse_iso

        with pytest.raises(ValueError):
            parse_iso("2026-13-45T99:99:99Z")


class TestPathHandling:
    def test_symlinks_are_not_followed(self, tmp_path):
        # A symlink to /etc would otherwise let an audited repository steer the
        # scanner outside its own tree.
        (tmp_path / "real.py").write_text("import os\n")
        target = tmp_path / "escape.py"
        try:
            os.symlink("/etc/passwd", str(target))
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")
        result = scan_tree(str(tmp_path))
        assert result.paths == ["real.py"]

    def test_traversal_strings_in_filenames_stay_relative(self, tmp_path):
        nested = tmp_path / "sub"
        nested.mkdir()
        (nested / "a.py").write_text("x = 1\n")
        result = scan_tree(str(tmp_path))
        for path in result.paths:
            assert not path.startswith("/")
            assert ".." not in path

    def test_vendor_directories_are_skipped(self, tmp_path):
        # A finding inside node_modules is not a finding about this server.
        (tmp_path / "server.py").write_text("x = 1\n")
        vendored = tmp_path / "node_modules" / "evil"
        vendored.mkdir(parents=True)
        (vendored / "bad.py").write_text("import os\nos.system('rm -rf /')\n")
        result = scan_tree(str(tmp_path))
        assert result.paths == ["server.py"]


class TestOutputLayoutCannotBeSheared:
    def test_absurd_repository_name_is_truncated_in_the_table(self):
        meta = RepoMeta(
            full_name="a" * 400,
            description=None,
            html_url="https://github.com/x",
            stars=1, forks=0, created_at=iso(10), pushed_at=iso(1),
            archived=False, license=None,
        )
        row = (meta, {"suspicious": False, "age_days": 10, "fork_ratio": 0.0})
        table = render_search_table([row])
        widths = {len(line) for line in table.splitlines() if line.startswith(("1  ", "#  "))}
        assert all(width < 200 for width in widths)

    def test_unicode_repository_name_does_not_crash_rendering(self):
        meta = RepoMeta(
            full_name="акме/виджет-🔥-mcp",
            description="описание",
            html_url="https://github.com/x",
            stars=5, forks=1, created_at=iso(10), pushed_at=iso(1),
            archived=False, license="MIT",
        )
        row = (meta, {"suspicious": False, "age_days": 10, "fork_ratio": 0.2})
        assert "mcp" in render_search_table([row])


class TestNoExecution:
    def test_analyzing_a_fixture_does_not_import_it(self):
        # The obfuscated fixture calls exec() at module scope. If anything in
        # mcp-vet imported what it analyzes, this test would run that payload.
        import sys

        before = set(sys.modules)
        audit_directory(fixture("obfuscated"))
        new = set(sys.modules) - before
        assert not any("server" == name.split(".")[-1] for name in new)

    def test_json_output_is_parseable_after_hostile_input(self):
        report = audit_directory(fixture("hostile_text"))
        parsed = json.loads(report.to_json())
        assert parsed["schema_version"]
        assert parsed["target"]
