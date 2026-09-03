"""MCP Registry integration and the provenance chain. All HTTP is mocked."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_vet import registry
from mcp_vet.http import FetchError
from mcp_vet.models import Severity, Status

from helpers import mock_response


def entry(name="ai.acme/widget", repo="https://github.com/acme/widget-mcp", **kw):
    """One registry row shaped like the live v0 API returns it."""
    server = {
        "name": name,
        "description": kw.get("description", "A widget server"),
        "version": kw.get("version", "1.0.0"),
    }
    if repo:
        server["repository"] = {"url": repo, "source": "github"}
    if "packages" in kw:
        server["packages"] = kw["packages"]
    if "remotes" in kw:
        server["remotes"] = kw["remotes"]
    return {
        "server": server,
        "_meta": {
            registry.OFFICIAL_META_KEY: {
                "status": kw.get("status", "active"),
                "isLatest": kw.get("is_latest", True),
                "publishedAt": "2026-05-05T14:01:01.659721Z",
            }
        },
    }


class TestParsing:
    def test_parses_the_live_schema_shape(self):
        server = registry._parse_server(
            entry(packages=[{"registryType": "pypi", "identifier": "widget",
                             "version": "1.0.0", "transport": {"type": "stdio"}}])
        )
        assert server.name == "ai.acme/widget"
        assert server.repository_url == "https://github.com/acme/widget-mcp"
        assert server.transports == ["stdio"]
        assert server.is_remote_only is False

    def test_remote_only_server_is_detected(self):
        server = registry._parse_server(
            entry(repo=None, remotes=[{"type": "streamable-http", "url": "https://api.acme.dev/mcp"}])
        )
        assert server.is_remote_only is True
        assert server.transports == ["streamable-http"]

    def test_registry_text_is_sanitized(self):
        server = registry._parse_server(entry(name="ai.\x1b[31macme\x1b[0m/widget"))
        assert "\x1b" not in server.name

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://github.com/Acme/Widget.git", "github.com/acme/widget"),
            ("git+https://github.com/acme/widget", "github.com/acme/widget"),
            ("https://github.com/acme/widget/", "github.com/acme/widget"),
            ("git@github.com:acme/widget.git", "github.com/acme/widget"),
            ("not a url", None),
            (None, None),
        ],
    )
    def test_repository_normalisation(self, url, expected):
        assert registry._normalize_repo(url) == expected


class TestSearch:
    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_uses_the_server_side_search_parameter(self, urlopen):
        urlopen.return_value = mock_response({"servers": [entry()], "metadata": {}})
        registry.search("widget", limit=5)
        called = urlopen.call_args[0][0].full_url
        assert "search=widget" in called

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_versions_of_one_server_collapse_to_one_row(self, urlopen):
        # The API returns every published version as its own entry.
        urlopen.return_value = mock_response({
            "servers": [
                entry(version="1.0.0", is_latest=False),
                entry(version="2.0.0", is_latest=True),
            ],
            "metadata": {},
        })
        results = registry.search("widget", limit=5)
        assert len(results) == 1
        assert results[0].version == "2.0.0"

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_find_by_repository_matches_on_the_declared_url(self, urlopen):
        urlopen.return_value = mock_response({
            "servers": [entry(name="ai.other/thing", repo="https://github.com/other/thing"),
                        entry()],
            "metadata": {},
        })
        found = registry.find_by_repository("https://github.com/acme/widget-mcp")
        assert found is not None and found.name == "ai.acme/widget"

    @patch("mcp_vet.http.urllib.request.urlopen")
    def test_find_by_repository_returns_none_when_absent(self, urlopen):
        urlopen.return_value = mock_response({"servers": [], "metadata": {}})
        assert registry.find_by_repository("https://github.com/acme/widget-mcp") is None


class TestProvenance:
    def test_matching_repository_is_not_flagged_but_is_not_called_safe(self):
        server = registry._parse_server(entry())
        assessment, findings = registry.assess_provenance(server, "acme/widget-mcp")
        assert assessment.severity is Severity.NOT_FLAGGED
        assert findings == []
        assert "not a review" in assessment.summary

    def test_mismatch_is_reported_explicitly(self):
        server = registry._parse_server(entry(repo="https://github.com/someone-else/widget"))
        assessment, findings = registry.assess_provenance(server, "acme/widget-mcp")
        assert assessment.severity is Severity.HIGH
        rule_ids = {f.rule_id for f in findings}
        assert "provenance.registry_source_mismatch" in rule_ids
        assert "Registry/source mismatch" in findings[0].title

    def test_missing_repository_is_medium(self):
        server = registry._parse_server(entry(repo=None))
        assessment, findings = registry.assess_provenance(server, "acme/widget-mcp")
        assert assessment.severity is Severity.MEDIUM
        assert "provenance.no_declared_source" in {f.rule_id for f in findings}

    def test_remote_only_server_gets_its_own_warning(self):
        server = registry._parse_server(
            entry(repo=None, remotes=[{"type": "streamable-http", "url": "https://api.acme.dev/mcp"}])
        )
        _, findings = registry.assess_provenance(server, "acme/widget-mcp")
        remote = [f for f in findings if f.rule_id == "provenance.remote_only_server"]
        assert remote
        assert "you run none of this code" in remote[0].title

    def test_non_active_status_is_flagged(self):
        server = registry._parse_server(entry(status="deleted"))
        _, findings = registry.assess_provenance(server, "acme/widget-mcp")
        assert "provenance.registry_status" in {f.rule_id for f in findings}

    def test_absence_from_the_registry_is_not_a_finding(self):
        # Most servers are simply not registered.
        assessment, findings = registry.assess_provenance(None, "acme/widget-mcp")
        assert assessment.status is Status.NOT_APPLICABLE
        assert findings == []
        assert "absence is not a finding" in assessment.summary

    def test_unreachable_registry_reads_as_unavailable_not_clean(self):
        assessment, findings = registry.assess_provenance(None, "acme/widget-mcp", lookup_failed=True)
        assert assessment.status is Status.UNAVAILABLE
        assert "not evidence either way" in assessment.summary
        assert findings == []
