"""GitHub client, repository trust signals, and the read-only guarantee.

The read-only tests below are the ones that encode the project's promise: no
output mcp-vet produces may look like a command that installs, clones or
writes anything. It reports; the human decides and acts.
"""
from __future__ import annotations

import io
import urllib.error
from unittest.mock import patch

import pytest

from mcp_vet import trust
from mcp_vet.audit import audit_directory
from mcp_vet.github import RepoMeta, fetch_extras, fetch_repo, search_repos
from mcp_vet.http import FetchError, NotFound, RateLimited
from mcp_vet.models import Severity
from mcp_vet.report import render_search_table, render_text
from mcp_vet.popularity import assess as popularity_assess

from helpers import NOW, fixture, iso, mock_response, repo_json


class TestRepoMetaMapping:
    def test_maps_the_fields_the_report_cites(self):
        meta = RepoMeta.from_github_json(repo_json(stargazers_count=42, forks_count=7))
        assert meta.full_name == "acme/widget-mcp"
        assert meta.stars == 42
        assert meta.forks == 7
        assert meta.license == "MIT"
        assert meta.owner_type == "Organization"

    def test_missing_license_is_none_not_empty_string(self):
        meta = RepoMeta.from_github_json(repo_json(license=None))
        assert meta.license is None

    def test_absent_optional_fields_get_defaults(self):
        minimal = {
            "full_name": "a/b", "html_url": "u",
            "created_at": iso(10), "pushed_at": iso(1),
        }
        meta = RepoMeta.from_github_json(minimal)
        assert meta.stars == 0 and meta.forks == 0
        assert meta.archived is False
        assert meta.topics == []


class TestNetworkLayer:
    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_fetch_repo_calls_the_right_url(self, urlopen):
        urlopen.return_value = mock_response(repo_json())
        meta = fetch_repo("acme/widget-mcp")
        assert meta.full_name == "acme/widget-mcp"
        assert urlopen.call_args[0][0].full_url == "https://api.github.com/repos/acme/widget-mcp"

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_search_repos_builds_a_list(self, urlopen):
        urlopen.return_value = mock_response({"items": [repo_json()]})
        results = search_repos("discord mcp", limit=5)
        assert len(results) == 1
        assert urlopen.call_args[0][0].full_url.startswith(
            "https://api.github.com/search/repositories?"
        )

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_404_raises_notfound_rather_than_exiting(self, urlopen):
        # The old implementation raised SystemExit from inside the request
        # helper, which made graceful degradation impossible for any caller.
        urlopen.side_effect = urllib.error.HTTPError(
            url="x", code=404, msg="Not Found", hdrs=None, fp=io.BytesIO(b"Not Found")
        )
        with pytest.raises(NotFound):
            fetch_repo("nope/nope")

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_rate_limit_raises_ratelimited_with_guidance(self, urlopen):
        urlopen.side_effect = urllib.error.HTTPError(
            url="x", code=403, msg="Forbidden", hdrs=None,
            fp=io.BytesIO(b'{"message": "API rate limit exceeded"}'),
        )
        with pytest.raises(RateLimited) as excinfo:
            fetch_repo("acme/widget")
        assert "GITHUB_TOKEN" in excinfo.value.message

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_malformed_json_raises_fetcherror(self, urlopen):
        cm = mock_response({})
        cm.__enter__.return_value.read.return_value = b"{not json"
        urlopen.return_value = cm
        with pytest.raises(FetchError):
            fetch_repo("acme/widget")

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_extras_degrade_per_call_instead_of_failing_the_audit(self, urlopen):
        urlopen.side_effect = urllib.error.URLError("offline")
        extras = fetch_extras("acme/widget")
        assert extras.contributors is None
        assert len(extras.errors) == 3   # contributors, releases, tags


class TestTrustSignals:
    def make(self, **kw):
        base = dict(
            full_name="acme/widget-mcp", description="d",
            html_url="https://github.com/acme/widget-mcp",
            stars=100, forks=30, created_at=iso(900), pushed_at=iso(1),
            archived=False, license="MIT",
        )
        base.update(kw)
        return RepoMeta(**base)

    def test_archived_is_reported(self):
        _, maintenance, findings = trust.assess(self.make(archived=True), now=NOW)
        assert "trust.archived" in {f.rule_id for f in findings}
        assert maintenance.severity is Severity.MEDIUM

    def test_stale_repository_is_reported(self):
        _, _, findings = trust.assess(self.make(pushed_at=iso(400)), now=NOW)
        assert "trust.stale" in {f.rule_id for f in findings}

    def test_not_stale_at_the_boundary(self):
        # > 180, not >=.
        _, _, findings = trust.assess(self.make(pushed_at=iso(180)), now=NOW)
        assert "trust.stale" not in {f.rule_id for f in findings}

    def test_missing_license_is_legal_not_safety(self):
        _, _, findings = trust.assess(self.make(license=None), now=NOW)
        finding = [f for f in findings if f.rule_id == "trust.no_license"][0]
        assert finding.severity is Severity.LOW
        assert "legal problem rather than a safety one" in finding.explanation

    def test_fork_mentions_typosquatting(self):
        _, _, findings = trust.assess(self.make(is_fork=True), now=NOW)
        finding = [f for f in findings if f.rule_id == "trust.is_fork"][0]
        assert "typosquat" in finding.explanation.lower()

    def test_very_new_repo_is_info_not_an_accusation(self):
        _, _, findings = trust.assess(self.make(created_at=iso(5)), now=NOW)
        finding = [f for f in findings if f.rule_id == "trust.very_new"][0]
        assert finding.severity is Severity.INFO
        assert "not suspicious in itself" in finding.explanation

    def test_healthy_repository_produces_no_trust_findings(self):
        _, _, findings = trust.assess(self.make(), now=NOW)
        assert findings == []


# The report may *mention* installing while telling the reader to go review
# first - that is the point. What it must never emit is text shaped like a
# command that performs one.
FORBIDDEN_ACTIONS = ("git clone", "cp -r", ".mcp.json", "~/.claude/skills", "git checkout")


class TestReportingStaysReadOnly:
    def test_audit_report_emits_no_install_action(self):
        text = render_text(audit_directory(fixture("exfil_server")), verbose=True).lower()
        for action in FORBIDDEN_ACTIONS:
            assert action not in text, f"report should never emit '{action}'"

    def test_clean_report_emits_no_install_action(self):
        text = render_text(audit_directory(fixture("clean_server"))).lower()
        for action in FORBIDDEN_ACTIONS:
            assert action not in text

    def test_search_table_emits_no_install_action(self):
        meta = RepoMeta.from_github_json(repo_json())
        table = render_search_table(
            [(meta, {"suspicious": True, "age_days": 30, "fork_ratio": 0.01})]
        ).lower()
        for action in FORBIDDEN_ACTIONS:
            assert action not in table

    def test_empty_search_table_is_handled(self):
        assert "No candidates found" in render_search_table([])
