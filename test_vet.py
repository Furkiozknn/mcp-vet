"""Tests for vet.py — no real network access, no `gh` CLI dependency.

Covers:
  * the suspicious-flag heuristic in isolation (clearly suspicious, clearly
    fine, and each of the 3 conditions failing individually vs. all firing
    at once, plus the exact boundary values)
  * evaluate()'s secondary signals (stale / license_missing / archived)
  * fetch_repo() / search_repos() against a mocked urllib.request.urlopen
  * report formatting stays read-only (contains no install/clone action)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import vet


NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)


def iso(days_ago: int) -> str:
    """Build an ISO timestamp `days_ago` days before NOW."""
    from datetime import timedelta

    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_meta(
    stars: int,
    forks: int,
    age_days: int,
    pushed_days_ago: int = 1,
    archived: bool = False,
    license_name: str | None = "MIT",
) -> vet.RepoMeta:
    return vet.RepoMeta(
        full_name="acme/widget-mcp",
        description="An example MCP server",
        html_url="https://github.com/acme/widget-mcp",
        stars=stars,
        forks=forks,
        created_at=iso(age_days),
        pushed_at=iso(pushed_days_ago),
        archived=archived,
        license=license_name,
    )


# --------------------------------------------------------------------------
# The heuristic itself
# --------------------------------------------------------------------------


class TestIsSuspicious:
    def test_clearly_suspicious(self):
        # High stars, very young, tiny fork ratio -> all three conditions hold.
        assert vet.is_suspicious(stars=5000, forks=100, created_at=iso(30), now=NOW) is True

    def test_clearly_fine(self):
        # Modest stars, old, healthy fork ratio -> none of the conditions hold.
        assert vet.is_suspicious(stars=500, forks=200, created_at=iso(1000), now=NOW) is False

    def test_fails_only_stars_condition(self):
        # Young + low fork ratio, but stars under the threshold.
        assert vet.is_suspicious(stars=1000, forks=10, created_at=iso(30), now=NOW) is False

    def test_fails_only_age_condition(self):
        # High stars + low fork ratio, but repo is old.
        assert vet.is_suspicious(stars=5000, forks=50, created_at=iso(400), now=NOW) is False

    def test_fails_only_fork_ratio_condition(self):
        # High stars + young, but a healthy fork ratio (>= 0.12).
        assert vet.is_suspicious(stars=5000, forks=700, created_at=iso(30), now=NOW) is False

    def test_all_three_barely_over_threshold(self):
        assert (
            vet.is_suspicious(stars=3001, forks=1, created_at=iso(179), now=NOW) is True
        )

    def test_boundary_stars_exactly_at_threshold_not_flagged(self):
        # stars > 3000 is strict; == 3000 must not flag.
        assert vet.is_suspicious(stars=3000, forks=1, created_at=iso(30), now=NOW) is False

    def test_boundary_age_exactly_at_threshold_not_flagged(self):
        # age < 180 is strict; == 180 must not flag.
        assert vet.is_suspicious(stars=5000, forks=1, created_at=iso(180), now=NOW) is False

    def test_boundary_fork_ratio_exactly_at_threshold_not_flagged(self):
        # forks/stars < 0.12 is strict; == 0.12 must not flag.
        assert vet.is_suspicious(stars=10000, forks=1200, created_at=iso(30), now=NOW) is False

    def test_zero_stars_never_flagged(self):
        assert vet.is_suspicious(stars=0, forks=0, created_at=iso(1), now=NOW) is False


class TestForkRatio:
    def test_normal(self):
        assert vet.fork_ratio(100, 1000) == pytest.approx(0.1)

    def test_zero_stars_is_zero_not_division_error(self):
        assert vet.fork_ratio(0, 0) == 0.0


class TestAgeDays:
    def test_basic(self):
        assert vet.age_days(iso(45), NOW) == 45


# --------------------------------------------------------------------------
# evaluate() — full vetting summary including secondary signals
# --------------------------------------------------------------------------


class TestEvaluate:
    def test_suspicious_repo_full_summary(self):
        meta = make_meta(stars=5000, forks=50, age_days=30, pushed_days_ago=2)
        result = vet.evaluate(meta, now=NOW)
        assert result["suspicious"] is True
        assert result["age_days"] == 30
        assert result["stale"] is False
        assert result["license_missing"] is False
        assert result["archived"] is False

    def test_stale_flag(self):
        meta = make_meta(stars=100, forks=50, age_days=1000, pushed_days_ago=200)
        result = vet.evaluate(meta, now=NOW)
        assert result["stale"] is True

    def test_not_stale_at_boundary(self):
        meta = make_meta(stars=100, forks=50, age_days=1000, pushed_days_ago=180)
        result = vet.evaluate(meta, now=NOW)
        assert result["stale"] is False  # > 180, not >=

    def test_license_missing_flag(self):
        meta = make_meta(stars=100, forks=50, age_days=1000, license_name=None)
        result = vet.evaluate(meta, now=NOW)
        assert result["license_missing"] is True

    def test_archived_flag(self):
        meta = make_meta(stars=100, forks=50, age_days=1000, archived=True)
        result = vet.evaluate(meta, now=NOW)
        assert result["archived"] is True

    def test_defaults_now_to_current_time_when_omitted(self):
        # Smoke test: omitting `now` should not raise, and should use "today".
        meta = make_meta(stars=10, forks=5, age_days=10)
        result = vet.evaluate(meta)
        assert isinstance(result["age_days"], int)
        assert result["age_days"] >= 10


# --------------------------------------------------------------------------
# RepoMeta.from_github_json
# --------------------------------------------------------------------------


class TestRepoMetaFromGithubJson:
    def test_maps_fields(self):
        data = {
            "full_name": "acme/widget-mcp",
            "description": "does widget things",
            "html_url": "https://github.com/acme/widget-mcp",
            "stargazers_count": 42,
            "forks_count": 7,
            "created_at": "2026-01-01T00:00:00Z",
            "pushed_at": "2026-08-01T00:00:00Z",
            "archived": False,
            "license": {"name": "MIT License"},
        }
        meta = vet.RepoMeta.from_github_json(data)
        assert meta.full_name == "acme/widget-mcp"
        assert meta.stars == 42
        assert meta.forks == 7
        assert meta.license == "MIT License"

    def test_missing_license_is_none(self):
        data = {
            "full_name": "acme/widget-mcp",
            "description": None,
            "html_url": "https://github.com/acme/widget-mcp",
            "stargazers_count": 1,
            "forks_count": 0,
            "created_at": "2026-01-01T00:00:00Z",
            "pushed_at": "2026-08-01T00:00:00Z",
            "archived": False,
            "license": None,
        }
        meta = vet.RepoMeta.from_github_json(data)
        assert meta.license is None


# --------------------------------------------------------------------------
# Network layer — mocked, no real HTTP calls
# --------------------------------------------------------------------------


def _mock_response(payload: dict):
    mock_cm = MagicMock()
    mock_cm.__enter__.return_value.read.return_value = json.dumps(payload).encode("utf-8")
    return mock_cm


class TestFetchRepo:
    @patch("vet.urllib.request.urlopen")
    def test_fetch_repo_builds_repo_meta(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(
            {
                "full_name": "acme/widget-mcp",
                "description": "widgets",
                "html_url": "https://github.com/acme/widget-mcp",
                "stargazers_count": 10,
                "forks_count": 2,
                "created_at": "2026-01-01T00:00:00Z",
                "pushed_at": "2026-08-01T00:00:00Z",
                "archived": False,
                "license": {"name": "MIT"},
            }
        )
        meta = vet.fetch_repo("acme/widget-mcp")
        assert meta.full_name == "acme/widget-mcp"
        assert meta.stars == 10
        called_url = mock_urlopen.call_args[0][0].full_url
        assert called_url == "https://api.github.com/repos/acme/widget-mcp"

    @patch("vet.urllib.request.urlopen")
    def test_fetch_repo_404_raises_system_exit(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="x", code=404, msg="Not Found", hdrs=None, fp=None
        )
        with pytest.raises(SystemExit):
            vet.fetch_repo("nope/nope")


class TestSearchRepos:
    @patch("vet.urllib.request.urlopen")
    def test_search_repos_builds_list(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response(
            {
                "items": [
                    {
                        "full_name": "acme/widget-mcp",
                        "description": "widgets",
                        "html_url": "https://github.com/acme/widget-mcp",
                        "stargazers_count": 10,
                        "forks_count": 2,
                        "created_at": "2026-01-01T00:00:00Z",
                        "pushed_at": "2026-08-01T00:00:00Z",
                        "archived": False,
                        "license": {"name": "MIT"},
                    }
                ]
            }
        )
        results = vet.search_repos("discord mcp", limit=5)
        assert len(results) == 1
        assert results[0].full_name == "acme/widget-mcp"
        called_url = mock_urlopen.call_args[0][0].full_url
        assert called_url.startswith("https://api.github.com/search/repositories?")


# --------------------------------------------------------------------------
# Reporting stays read-only: no install/clone verbs anywhere in the output
# --------------------------------------------------------------------------


# The script may *mention* "install"/"clone" while telling the human to go
# read the source first (that's the point) — what it must never do is emit
# text shaped like an actual command that performs one.
FORBIDDEN_ACTIONS = ("git clone", "cp -r", ".mcp.json", "~/.claude/skills", "git checkout")


class TestReportingIsReadOnly:
    def test_check_report_has_no_install_action(self):
        meta = make_meta(stars=5000, forks=50, age_days=30)
        result = vet.evaluate(meta, now=NOW)
        report = vet.format_check_report(meta, result)
        lowered = report.lower()
        for action in FORBIDDEN_ACTIONS:
            assert action not in lowered, f"report should never emit '{action}'"

    def test_search_table_has_no_install_action(self):
        meta = make_meta(stars=5000, forks=50, age_days=30)
        result = vet.evaluate(meta, now=NOW)
        table = vet.format_search_table([(meta, result)])
        lowered = table.lower()
        for action in FORBIDDEN_ACTIONS:
            assert action not in lowered, f"table should never emit '{action}'"

    def test_search_table_handles_empty_results(self):
        assert "No candidates found" in vet.format_search_table([])


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------


class TestCli:
    def test_check_command_prints_report(self, capsys, monkeypatch):
        meta = make_meta(stars=5000, forks=50, age_days=30)
        monkeypatch.setattr(vet, "fetch_repo", lambda repo: meta)
        exit_code = vet.main(["check", "acme/widget-mcp"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "acme/widget-mcp" in captured.out
        assert "SUSPICIOUS" in captured.out

    def test_search_command_prints_table(self, capsys, monkeypatch):
        meta = make_meta(stars=100, forks=50, age_days=1000)
        monkeypatch.setattr(vet, "search_repos", lambda query, limit: [meta])
        exit_code = vet.main(["search", "discord mcp", "--limit", "3"])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "acme/widget-mcp" in captured.out

    def test_missing_command_errors(self):
        with pytest.raises(SystemExit):
            vet.main([])
