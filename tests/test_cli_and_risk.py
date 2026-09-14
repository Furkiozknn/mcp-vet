"""Risk synthesis, the CLI surface, exit codes, and the JSON contract."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from mcp_vet import risk
from mcp_vet.audit import audit_directory, audit_repository
from mcp_vet.cli import main
from mcp_vet.github import RepoMeta
from mcp_vet.http import RateLimited
from mcp_vet.models import (
    Area,
    AuditReport,
    Evidence,
    Confidence,
    Finding,
    SCHEMA_VERSION,
    Severity,
    Status,
)

from helpers import fixture, mock_response, repo_json


def finding(severity, confidence=Confidence.HIGH, area=Area.SOURCE_CODE, rule_id="x"):
    return Finding(area=area, severity=severity, confidence=confidence,
                   title="t", explanation="e", rule_id=rule_id)


class TestSeverityAndConfidenceStaySeparate:
    def test_low_confidence_demotes_the_headline_only(self):
        report = AuditReport(target="a/b", findings=[finding(Severity.CRITICAL, Confidence.LOW)])
        risk.finalize(report)
        assert report.overall is Severity.HIGH          # headline demoted
        assert report.findings[0].severity is Severity.CRITICAL  # finding untouched
        assert report.area(Area.SOURCE_CODE).severity is Severity.CRITICAL

    def test_high_confidence_is_not_demoted(self):
        report = AuditReport(target="a/b", findings=[finding(Severity.CRITICAL, Confidence.HIGH)])
        risk.finalize(report)
        assert report.overall is Severity.CRITICAL

    def test_worst_area_wins_rather_than_an_average(self):
        report = AuditReport(target="a/b", findings=[
            finding(Severity.INFO, area=Area.MAINTENANCE, rule_id="a"),
            finding(Severity.INFO, area=Area.REPOSITORY_TRUST, rule_id="b"),
            finding(Severity.HIGH, area=Area.NETWORK, rule_id="c"),
        ])
        risk.finalize(report)
        assert report.overall is Severity.HIGH


class TestExitCodes:
    @pytest.mark.parametrize("severity,expected", [
        (Severity.NOT_FLAGGED, 0),
        (Severity.INFO, 0),
        (Severity.LOW, 1),
        (Severity.MEDIUM, 1),
        (Severity.HIGH, 2),
        (Severity.CRITICAL, 3),
    ])
    def test_mapping_is_stable(self, severity, expected):
        assert risk.exit_code_for(severity) == expected

    def test_clean_fixture_exits_zero(self, capsys):
        assert main(["audit", "--offline", "--path", fixture("clean_server")]) == 0

    def test_exfil_fixture_exits_two(self, capsys):
        assert main(["audit", "--offline", "--path", fixture("exfil_server")]) == 2

    def test_poisoned_fixture_exits_three(self, capsys):
        assert main(["audit", "--offline", "--path", fixture("poisoned_server")]) == 3

    def test_tool_error_is_four_not_zero(self, capsys):
        # "could not look" must never share an exit code with "found nothing",
        # or a broken CI gate reads as a passing one.
        assert main(["audit", "--offline"]) == risk.EXIT_ERROR

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_rate_limit_exits_four_with_a_useful_message(self, urlopen, capsys):
        urlopen.side_effect = RateLimited("rate limit reached; set GITHUB_TOKEN")
        assert main(["check", "acme/widget"]) == risk.EXIT_ERROR
        assert "GITHUB_TOKEN" in capsys.readouterr().err

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_malformed_repo_response_exits_four_with_no_traceback(self, urlopen, capsys):
        # An empty-but-valid JSON body from GitHub reached RepoMeta.from_github_json
        # as a bare dict and crashed with KeyError, which argparse's caller never
        # catches - the process would exit non-zero anyway, but with a stack
        # trace on stderr instead of the one-line message every other failure gets.
        urlopen.return_value = mock_response({})
        assert main(["check", "acme/widget"]) == risk.EXIT_ERROR
        err = capsys.readouterr().err
        assert err.startswith("error:")
        assert "Traceback" not in err


class TestNeverSaysSafe:
    def test_no_recommendation_uses_the_word_safe_affirmatively(self):
        for severity in Severity:
            text = risk.recommendation_for(severity).lower()
            assert "is safe" not in text
            assert "guaranteed" not in text

    def test_clean_verdict_states_the_limitation_inline(self):
        text = risk.recommendation_for(Severity.NOT_FLAGGED)
        assert "not the same as safe" in text.lower()

    def test_limitations_are_present_even_on_a_clean_report(self):
        report = audit_directory(fixture("clean_server"))
        assert report.limitations
        assert any("cannot prove" in lim or "No static analyzer" in lim
                   for lim in report.limitations)


class TestStatusIsNotSeverity:
    def test_offline_mode_marks_github_areas_not_checked(self):
        report = audit_directory(fixture("clean_server"))
        for area in (Area.POPULARITY_INTEGRITY, Area.REPOSITORY_TRUST, Area.PROVENANCE):
            assert report.area(area).status is Status.NOT_CHECKED

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_metadata_only_audit_says_source_was_not_analyzed(self, urlopen):
        urlopen.return_value = mock_response(repo_json())
        report = audit_repository("acme/widget-mcp", local_path=None,
                                  check_registry=False, fetch_repo_extras=False)
        assert report.area(Area.SOURCE_CODE).status is Status.NOT_CHECKED
        assert any("Source code was NOT analyzed" in lim for lim in report.limitations)


class TestJsonContract:
    def test_schema_version_is_present_and_stable(self):
        payload = json.loads(audit_directory(fixture("exfil_server")).to_json())
        assert payload["schema_version"] == SCHEMA_VERSION

    def test_top_level_keys(self):
        payload = json.loads(audit_directory(fixture("exfil_server")).to_json())
        assert set(payload) == {
            "schema_version", "target", "source_url", "version", "overall",
            "recommendation", "areas", "findings", "capabilities", "endpoints",
            "credentials", "dataflows", "limitations", "notes",
        }

    def test_every_finding_carries_the_fields_a_consumer_keys_off(self):
        payload = json.loads(audit_directory(fixture("exfil_server")).to_json())
        assert payload["findings"]
        for item in payload["findings"]:
            assert item["rule_id"]
            assert item["area"]
            assert item["severity"] in {s.value for s in Severity}
            assert item["confidence"] in {c.value for c in Confidence}
            assert item["explanation"]

    def test_findings_are_ordered_most_severe_first(self):
        payload = json.loads(audit_directory(fixture("exfil_server")).to_json())
        ranks = [Severity(item["severity"]).rank for item in payload["findings"]]
        assert ranks == sorted(ranks, reverse=True)

    def test_output_is_byte_stable_across_runs(self):
        # CI diffs two reports; unstable ordering would make every run a change.
        first = audit_directory(fixture("exfil_server")).to_json()
        second = audit_directory(fixture("exfil_server")).to_json()
        assert first == second

    def test_json_flag_emits_only_json(self, capsys):
        main(["audit", "--offline", "--path", fixture("clean_server"), "--json"])
        json.loads(capsys.readouterr().out)


class TestCliSurface:
    def test_quiet_prints_two_lines(self, capsys):
        main(["audit", "--offline", "--path", fixture("clean_server"), "--quiet"])
        assert len(capsys.readouterr().out.strip().splitlines()) == 2

    def test_verbose_includes_snippets(self, capsys):
        main(["audit", "--offline", "--path", fixture("exfil_server"), "--verbose"])
        assert "|" in capsys.readouterr().out

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_check_reports_metadata_and_says_it_read_no_source(self, urlopen, capsys):
        urlopen.return_value = mock_response(repo_json())
        assert main(["check", "acme/widget-mcp"]) == 0
        out = capsys.readouterr().out
        assert "acme/widget-mcp" in out
        assert "no source was read" in out.lower()

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_search_table_labels_the_flag_as_popularity_only(self, urlopen, capsys):
        urlopen.return_value = mock_response(
            {"items": [repo_json(stargazers_count=5000, forks_count=50,
                                 created_at="2026-08-01T00:00:00Z")]}
        )
        main(["search", "widget mcp"])
        out = capsys.readouterr().out
        assert "POPULARITY-FLAGGED" in out
        assert "not vetted" in out

    def test_missing_subcommand_exits_nonzero(self):
        with pytest.raises(SystemExit):
            main([])

    def test_report_command_defaults_to_json(self, capsys):
        main(["report", "--offline", "--path", fixture("clean_server")])
        json.loads(capsys.readouterr().out)


class TestNarrowCodePage:
    """A console that cannot draw the report's glyphs must cost a glyph, not
    the report.

    `mcp-vet audit` died on a Turkish Windows console (cp1254) before printing
    anything - UnicodeEncodeError on the box-drawing rule under the heading.
    An auditor that prints nothing is read as a broken tool, and the audit
    gets skipped, which is the worst possible failure for this program.
    """

    @staticmethod
    def _cp1254_stream():
        import io

        return io.TextIOWrapper(io.BytesIO(), encoding="cp1254", errors="strict", newline="")

    def test_the_narrow_stream_really_does_raise(self):
        """Prove the rest of this class is not vacuous."""
        stream = self._cp1254_stream()
        with pytest.raises(UnicodeEncodeError):
            stream.write("─" * 10)
            stream.flush()

    def test_audit_survives_a_narrow_console(self, monkeypatch):
        import sys

        stream = self._cp1254_stream()
        monkeypatch.setattr(sys, "stdout", stream)
        monkeypatch.setattr(sys, "stderr", stream)
        code = main(["audit", "--offline", "--path", fixture("clean_server")])
        sys.stdout.flush()
        assert code == 0
        assert stream.encoding.lower() == "utf-8"

    def test_narrow_console_does_not_change_the_exit_code(self, monkeypatch):
        """Severity exit codes are the CI contract; hardening must not move them."""
        import sys

        stream = self._cp1254_stream()
        monkeypatch.setattr(sys, "stdout", stream)
        monkeypatch.setattr(sys, "stderr", stream)
        assert main(["audit", "--offline", "--path", fixture("poisoned_server")]) == 3

    def test_replacement_never_emits_an_escape_sequence(self, monkeypatch):
        """SECURITY.md promises no terminal escapes in output; replacing an
        unencodable glyph must not smuggle one in."""
        import sys

        stream = self._cp1254_stream()
        monkeypatch.setattr(sys, "stdout", stream)
        monkeypatch.setattr(sys, "stderr", stream)
        main(["audit", "--offline", "--path", fixture("hostile_text"), "--verbose"])
        sys.stdout.flush()
        ham = stream.buffer.getvalue()
        for kotu in (b"\x1b", b"\x00", b"\x07"):
            assert kotu not in ham, f"escape sequence leaked: {kotu!r}"


class TestFileRole:
    """A finding outside the shipped server must not set the headline.

    Auditing three widely-installed MCP servers produced a HIGH on each, and
    every one of the three sat outside the code that runs:

        github/github-mcp-server   pkg/utils/api_test.go
        GLips/Figma-Context-MCP    .github/ISSUE_TEMPLATE/bug_report.md
        microsoft/playwright-mcp   roll.js   (a release script)

    Telling a reader "HIGH: contacts a webhook-capture destination" about a bug
    report template is how a security tool trains people to ignore it.
    """

    @pytest.mark.parametrize(
        "path,beklenen",
        [
            ("pkg/utils/api_test.go", "test"),
            ("src/tests/server.test.ts", "test"),
            ("tests/fixtures/evil/payload.py", "test"),
            ("conftest.py", "test"),
            (".github/ISSUE_TEMPLATE/bug_report.md", "docs"),
            ("README.md", "docs"),
            ("docs/install.mdx", "docs"),
            ("scripts/scan-hidden-chars.mjs", "dev"),
            (".github/workflows/ci.yml", "dev"),
            ("examples/demo/app.py", "dev"),
            ("src/server.ts", "shipped"),
            ("mcp_vet/cli.py", "shipped"),
            ("index.js", "shipped"),
        ],
    )
    def test_paths_classify(self, path, beklenen):
        from mcp_vet.scanning import file_role

        assert file_role(path) == beklenen

    def test_root_dev_script_stays_shipped(self):
        """Deliberate: a root script with an ordinary name cannot be told apart
        from an entry point by path, and guessing from the name risks marking
        real server code as tooling. Over-reporting is the survivable error."""
        from mcp_vet.scanning import file_role

        assert file_role("roll.js") == "shipped"

    @staticmethod
    def _bulgu(path):
        return Finding(
            area=Area.SOURCE_CODE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="deneme",
            explanation="deneme",
            evidence=[Evidence(path=path, line=1)],
        )

    def test_headline_ignores_non_shipped_findings(self):
        from mcp_vet.risk import overall_severity

        assert overall_severity([self._bulgu("pkg/utils/api_test.go")]) == Severity.NOT_FLAGGED
        assert overall_severity([self._bulgu(".github/ISSUE_TEMPLATE/bug.md")]) == Severity.NOT_FLAGGED

    def test_headline_still_rises_for_shipped_findings(self):
        from mcp_vet.risk import overall_severity

        assert overall_severity([self._bulgu("src/server.ts")]) == Severity.HIGH

    def test_non_shipped_finding_keeps_its_severity_everywhere_else(self):
        """Scoping the headline is not suppression: the finding is still HIGH
        in the list and in its area."""
        from mcp_vet.risk import area_severities

        f = self._bulgu("pkg/utils/api_test.go")
        assert f.severity == Severity.HIGH
        assert area_severities([f])[Area.SOURCE_CODE] == Severity.HIGH

    def test_finding_without_a_path_counts_as_shipped(self):
        """A manifest-level observation has no file. Dropping it from the
        verdict would be a silent false negative."""
        from mcp_vet.risk import overall_severity

        f = Finding(
            area=Area.INSTALLATION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="deneme",
            explanation="deneme",
            evidence=[],
        )
        assert overall_severity([f]) == Severity.HIGH


class TestPipeToShellPrecision:
    """A shell line can contain `curl | sh` without ever running it.

    Both of these were reported CRITICAL on real repositories:

        run-server.sh:342   echo "   curl https://pyenv.run | bash" >&2
        install.sh:7        #   curl -fsSL .../install.sh | bash

    The first prints advice, the second is a usage comment. Calling either
    CRITICAL is how a reader learns that CRITICAL means nothing here.
    """

    @pytest.mark.parametrize(
        "path,line,calisiyor",
        [
            ("install.sh", "#   curl -fsSL https://x/i.sh | bash", False),
            ("run-server.sh", '  echo "curl https://pyenv.run | bash" >&2', False),
            ("setup.sh", "   printf 'curl https://x | sh'", False),
            ("Dockerfile", "RUN curl -o- https://x/i.sh | bash", True),
            ("setup.sh", "curl -sSf https://astral.sh/uv/install.sh | sh", True),
            # `echo` bir kelime olarak baslamali; `echoserver` bir komut adi.
            ("x.sh", "echoserver --url https://x | bash", True),
        ],
    )
    def test_only_executing_lines_count(self, path, line, calisiyor):
        from mcp_vet.install import _line_executes_pipe

        assert _line_executes_pipe(path, line) is calisiyor

    def test_markdown_is_not_filtered(self):
        """`curl | bash` in a README is the project telling you to run it,
        which is precisely the thing worth flagging."""
        from mcp_vet.install import _line_executes_pipe

        assert _line_executes_pipe("README.md", "#  curl https://x | bash") is True

    def test_pattern_has_no_stray_control_character(self):
        """Regression: written through a heredoc once, `\b` became a literal
        backspace (0x08) and the echo filter silently never matched."""
        from mcp_vet.install import _PRINTS_IT

        assert "\x08" not in _PRINTS_IT.pattern
