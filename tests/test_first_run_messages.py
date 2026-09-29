"""What a first-time user sees when the first command is wrong.

The exit codes are the contract and are pinned elsewhere; these tests pin the
words around them. Every failure here used to be a correct exit 4 with a
message that named the problem and not the next thing to type.

The mistake that started it: `mcp-vet audit ./checkout`. `./checkout` passed the
owner/repo pattern (`.` is in the character class), so it reached the GitHub API
as `/repos/./checkout` and came back as
`error: not found - not found: https://api.github.com/repos/./checkout`.
"""
from __future__ import annotations

import io
import urllib.error
from unittest.mock import patch

import pytest

from mcp_vet import risk
from mcp_vet.cli import build_parser, main, valid_owner_repo

from helpers import fixture


class TestDotSegmentsAreNotNames:
    @pytest.mark.parametrize("repo", [
        "./checkout", "../checkout", "acme/.", "acme/..", "..", "../..", "./.",
    ])
    def test_valid_owner_repo_refuses_them(self, repo):
        assert not valid_owner_repo(repo)

    @pytest.mark.parametrize("repo", ["acme/widget", "a.b/c-d_e", "acme/.github", "acme/widget.py"])
    def test_real_names_with_dots_still_pass(self, repo):
        assert valid_owner_repo(repo)

    @pytest.mark.parametrize("repo", ["./checkout", "../checkout", "acme/.."])
    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_no_request_is_made_for_them(self, urlopen, repo, capsys):
        assert main(["audit", repo]) == risk.EXIT_ERROR
        assert urlopen.call_count == 0
        assert capsys.readouterr().err.startswith("error: invalid repository")


class TestFolderTypedAsRepo:
    def test_a_dot_slash_path_is_pointed_at_offline_path(self, capsys):
        assert main(["audit", "./checkout"]) == risk.EXIT_ERROR
        err = capsys.readouterr().err
        assert "mcp-vet audit --offline --path ./checkout" in err

    def test_an_existing_bare_folder_name_gets_the_same_hint(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "checkout").mkdir()
        monkeypatch.chdir(tmp_path)
        assert main(["audit", "checkout"]) == risk.EXIT_ERROR
        assert "mcp-vet audit --offline --path checkout" in capsys.readouterr().err

    def test_a_windows_path_gets_the_hint(self, capsys):
        assert main(["check", "C:\\src\\server"]) == risk.EXIT_ERROR
        assert "--offline --path" in capsys.readouterr().err

    def test_a_plain_typo_gets_no_path_hint(self, capsys):
        assert main(["check", "acme"]) == risk.EXIT_ERROR
        assert "--offline" not in capsys.readouterr().err

    def test_the_hint_does_not_echo_an_escape_sequence(self, capsys):
        assert main(["audit", "./x\x1b]8;;http://evil/\x07"]) == risk.EXIT_ERROR
        assert "\x1b" not in capsys.readouterr().err


class TestPathErrorsSayWhy:
    def test_a_missing_path_says_it_does_not_exist(self, tmp_path, capsys):
        assert main(["audit", "--offline", "--path", str(tmp_path / "nope")]) == 4
        err = capsys.readouterr().err
        assert "is not a directory" in err
        assert "does not exist" in err

    def test_a_file_says_pass_the_folder(self, tmp_path, capsys):
        target = tmp_path / "server.py"
        target.write_text("x = 1\n")
        assert main(["audit", "--offline", "--path", str(target)]) == 4
        err = capsys.readouterr().err
        assert "is not a directory" in err
        assert "it is a file" in err


class TestMissingArgumentsShowTheCommand:
    def test_offline_without_path_shows_an_example(self, capsys):
        assert main(["audit", "--offline"]) == 4
        err = capsys.readouterr().err
        assert err.startswith("error: --offline requires --path")
        assert "mcp-vet audit --offline --path ./checkout" in err

    def test_audit_with_nothing_shows_both_forms(self, capsys):
        assert main(["audit"]) == 4
        err = capsys.readouterr().err
        assert "--offline --path ./checkout" in err
        assert "owner/repo --path ./checkout" in err


def _http_error(code: int):
    return urllib.error.HTTPError("https://api.github.com/x", code, "x", {}, io.BytesIO(b""))


class TestNetworkFailures:
    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_not_found_is_said_once_with_a_spelling_hint(self, urlopen, capsys):
        urlopen.side_effect = _http_error(404)
        assert main(["check", "acme/widget"]) == risk.EXIT_ERROR
        err = capsys.readouterr().err
        assert err.count("not found") == 1
        assert "https://api.github.com/repos/acme/widget" in err
        assert "private" in err

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_unreachable_points_at_offline(self, urlopen, capsys):
        urlopen.side_effect = urllib.error.URLError("connection refused")
        assert main(["check", "acme/widget"]) == risk.EXIT_ERROR
        err = capsys.readouterr().err
        assert err.startswith("error: could not reach")
        assert "--offline" in err

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_a_rate_limit_gets_no_offline_hint(self, urlopen, capsys):
        urlopen.side_effect = _http_error(429)
        assert main(["check", "acme/widget"]) == risk.EXIT_ERROR
        err = capsys.readouterr().err
        assert "GITHUB_TOKEN" in err
        assert "no network?" not in err


class TestHelpIsUseful:
    def _help(self, argv, capsys):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 0
        return capsys.readouterr().out

    def test_top_level_help_starts_with_a_command_that_works(self, capsys):
        out = self._help(["--help"], capsys)
        assert "mcp-vet audit --offline --path ./checkout" in out
        assert "git clone --depth 1" in out

    def test_top_level_help_keeps_the_exit_code_contract(self, capsys):
        out = self._help(["--help"], capsys)
        assert "0 nothing above INFO" in out
        assert "4 mcp-vet could not complete" in out

    def test_top_level_help_does_not_call_a_clean_run_safe(self, capsys):
        assert "is not 'safe'" in self._help(["--help"], capsys)

    @pytest.mark.parametrize("command", ["search", "registry", "check", "audit", "diff", "report"])
    def test_every_subcommand_has_help(self, command, capsys):
        assert self._help([command, "--help"], capsys).startswith(f"usage: mcp-vet {command}")

    @pytest.mark.parametrize("command,needle", [
        ("audit", "mcp-vet audit --offline --path ./checkout"),
        ("diff", "--before-path ./v1.2.0 --after-path ./v1.3.0"),
        ("report", "mcp-vet report --offline --path ./checkout"),
    ])
    def test_subcommands_with_examples_show_them(self, command, needle, capsys):
        assert needle in self._help([command, "--help"], capsys)

    def test_report_flags_are_described(self):
        """`report --path` used to be the one flag with no help text at all."""
        parser = build_parser()
        report = parser._subparsers._group_actions[0].choices["report"]
        for action in report._actions:
            assert action.help, f"{action.option_strings or action.dest} has no help"

    def test_a_usage_error_names_the_help(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["audit", "--no-such-flag"])
        assert exc.value.code == 4
        assert "--help" in capsys.readouterr().err

    def test_the_description_is_wrapped_and_the_examples_are_not(self, capsys):
        out = self._help(["--help"], capsys)
        assert max(len(line) for line in out.splitlines() if not line.startswith("  mcp-vet")) < 100


class TestNothingChangedForScripts:
    """The words moved; the contract did not."""

    def test_clean_still_exits_zero(self):
        assert main(["audit", "--offline", "--path", fixture("clean_server")]) == 0

    def test_json_still_has_no_hint_text_on_stdout(self, capsys):
        main(["report", "--offline", "--path", fixture("exfil_server")])
        out = capsys.readouterr().out
        assert out.lstrip().startswith("{")
        assert "hint:" not in out
