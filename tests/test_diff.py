"""Version diff: did this release gain capability it did not have before?

The update nobody re-reads is the dangerous one - fine at v1.2.0, approved,
and quietly growing shell execution at v1.3.0. These tests pin that detection
and, just as importantly, pin that an unchanged version stays quiet.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_vet import diff
from mcp_vet.cli import main
from mcp_vet.models import Severity

from helpers import fixture, mock_response


class TestLocalDiff:
    def setup_method(self):
        self.result = diff.diff_local(
            fixture("clean_server"), fixture("exfil_server"),
            before_ref="v1.2.0", after_ref="v1.3.0",
        )

    def test_new_capabilities_are_listed(self):
        assert set(self.result.capabilities_added) >= {
            "shell.execute", "process.spawn", "environment.read"
        }

    def test_new_credentials_are_listed(self):
        assert set(self.result.credentials_added) == {"GITHUB_TOKEN", "OPENAI_API_KEY"}

    def test_new_destination_is_listed(self):
        assert "telemetry-collect.example.net" in self.result.endpoints_added

    def test_shell_execution_appearing_is_high(self):
        findings = {f.rule_id: f for f in self.result.findings}
        assert findings["diff.capability_added.shell.execute"].severity is Severity.HIGH

    def test_findings_name_both_refs(self):
        finding = [f for f in self.result.findings if "shell.execute" in f.rule_id][0]
        assert "v1.2.0" in finding.title
        assert "v1.3.0" in finding.explanation

    def test_risk_increase_is_detected(self):
        assert self.result.risk_increased is True

    def test_full_tree_mode_is_recorded(self):
        assert self.result.mode == "local"


class TestNoChange:
    def test_identical_trees_report_nothing_gained(self):
        result = diff.diff_local(fixture("clean_server"), fixture("clean_server"))
        assert result.capabilities_added == []
        assert result.credentials_added == []
        assert result.findings == []
        assert result.risk_increased is False

    def test_output_says_quiet_is_not_the_same_as_unchanged(self):
        result = diff.diff_local(fixture("clean_server"), fixture("clean_server"))
        text = diff.render(result)
        assert "not the same as 'no meaningful change'" in text


class TestDroppedCapability:
    def test_losing_a_capability_is_reported_too(self):
        # A server that stops needing your token is worth knowing about.
        result = diff.diff_local(fixture("exfil_server"), fixture("clean_server"))
        assert "shell.execute" in result.capabilities_removed
        assert set(result.credentials_removed) == {"GITHUB_TOKEN", "OPENAI_API_KEY"}


class TestRefDiff:
    @patch("mcp_vet.diff.fetch_file")
    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_only_changed_files_are_fetched(self, urlopen, fetch_file):
        urlopen.return_value = mock_response({
            "files": [{"filename": "server.py"}, {"filename": "README.md"}]
        })
        fetch_file.side_effect = lambda repo, path, ref=None: (
            "import os\nos.system('x')\n" if ref == "v2" else "x = 1\n"
        )
        result = diff.diff_refs("acme/widget", "v1", "v2")
        # README.md is not a source extension, so it is not fetched.
        assert result.changed_files == ["server.py"]
        assert "shell.execute" in result.capabilities_added

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_refs_mode_states_its_own_blind_spot(self, urlopen):
        urlopen.return_value = mock_response({"files": []})
        result = diff.diff_refs("acme/widget", "v1", "v2")
        assert result.mode == "refs"
        assert any("did not change" in lim for lim in result.limitations)

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_refs_with_slashes_are_url_encoded(self, urlopen):
        urlopen.return_value = mock_response({"files": []})
        diff.diff_refs("acme/widget", "release/1.2", "release/1.3")
        url = urlopen.call_args[0][0].full_url
        assert "release%2F1.2...release%2F1.3" in url

    @patch("mcp_vet.diff.fetch_file")
    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_enormous_change_is_truncated_and_says_so(self, urlopen, fetch_file):
        urlopen.return_value = mock_response(
            {"files": [{"filename": f"f{i}.py"} for i in range(200)]}
        )
        fetch_file.return_value = "x = 1\n"
        result = diff.diff_refs("acme/widget", "v1", "v2")
        assert result.truncated is True
        assert any("better reviewed as a fresh audit" in lim for lim in result.limitations)


class TestCli:
    def test_local_diff_exits_two_when_shell_execution_appears(self, capsys):
        code = main(["diff", "--before-path", fixture("clean_server"),
                     "--after-path", fixture("exfil_server")])
        assert code == 2
        assert "shell.execute" in capsys.readouterr().out

    def test_unchanged_diff_exits_zero(self, capsys):
        code = main(["diff", "--before-path", fixture("clean_server"),
                     "--after-path", fixture("clean_server")])
        assert code == 0

    def test_labels_default_to_directory_names(self, capsys):
        main(["diff", "--before-path", fixture("clean_server"),
              "--after-path", fixture("exfil_server")])
        assert "clean_server -> exfil_server" in capsys.readouterr().out

    def test_one_sided_paths_are_rejected(self, capsys):
        assert main(["diff", "--before-path", fixture("clean_server")]) == 4

    def test_option_abbreviation_is_disabled(self):
        # `--before` must NOT silently resolve to `--before-path`: a mistyped
        # flag in a security tool has to fail rather than mean something else.
        with pytest.raises(SystemExit):
            main(["diff", "--before", fixture("clean_server"),
                  "--after-path", fixture("exfil_server")])
