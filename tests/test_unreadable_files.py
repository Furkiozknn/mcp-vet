"""A file the operating system will not let mcp-vet read is not a binary file.

Found on Windows by denying read access to one file of a checkout: the report
listed it under "1 binary file(s) were not analyzed" and rated the tree
NOT_FLAGGED. Two things were wrong. The reason was false - the file was source
code - and the other read failure (a file that cannot even be sized) skipped
the file without a word. Skipped files are reported precisely because an
attacker who knows the limits would hide behind them; a wrong reason is a
softer version of the same hole.
"""
from __future__ import annotations

import builtins
import json

import pytest

from mcp_vet import scanning
from mcp_vet.audit import audit_directory
from mcp_vet.cli import main


@pytest.fixture
def one_unreadable(tmp_path, monkeypatch):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text("import os\nos.system('x')\n", encoding="utf-8")
    (tmp_path / "logo.py").write_bytes(b"\x00\x01\x02binary")
    real_open = builtins.open

    def refusing_open(file, *args, **kwargs):
        if str(file).endswith("secret.py"):
            raise PermissionError(13, "Permission denied", str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(scanning, "open", refusing_open, raising=False)
    return tmp_path


def test_it_is_filed_as_unreadable_not_binary(one_unreadable):
    result = scanning.scan_tree(str(one_unreadable))
    assert result.skipped_unreadable == ["secret.py"]
    assert result.skipped_binary == ["logo.py"]
    assert [f.path for f in result.files] == ["ok.py"]


def test_the_report_says_so(one_unreadable):
    report = audit_directory(str(one_unreadable))
    assert any("could not be read" in text for text in report.limitations)
    assert report.notes["skipped_unreadable"] == ["secret.py"]
    # ... and the binary file is still described as binary
    assert any("binary file(s)" in text for text in report.limitations)


def test_it_reaches_the_json(one_unreadable, capsys):
    main(["report", "--offline", "--path", str(one_unreadable)])
    assert json.loads(capsys.readouterr().out)["notes"]["skipped_unreadable"] == ["secret.py"]


def test_a_file_that_cannot_be_sized_is_reported_too(tmp_path, monkeypatch):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "gone.py").write_text("y = 2\n", encoding="utf-8")
    real_getsize = scanning.os.path.getsize

    def flaky(path):
        if str(path).endswith("gone.py"):
            raise OSError("stat failed")
        return real_getsize(path)

    monkeypatch.setattr(scanning.os.path, "getsize", flaky)
    result = scanning.scan_tree(str(tmp_path))
    assert result.skipped_unreadable == ["gone.py"]


def test_a_readable_tree_reports_nothing_unreadable(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    report = audit_directory(str(tmp_path))
    assert "skipped_unreadable" not in report.notes
    assert not any("could not be read" in text for text in report.limitations)
