"""The star/fork/age heuristic.

These are the original vet.py tests, preserved assertion for assertion after
the logic moved into mcp_vet.popularity. The thresholds and the strict
comparisons at each boundary are the contract every report cites by value, so
they are pinned here rather than left to drift.
"""
from __future__ import annotations

import pytest

from mcp_vet import popularity
from mcp_vet.github import RepoMeta
from mcp_vet.models import Severity

from helpers import NOW, iso


def make_meta(stars, forks, age_days, pushed_days_ago=1, archived=False, license_name="MIT"):
    return RepoMeta(
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


class TestIsSuspicious:
    def test_clearly_suspicious(self):
        assert popularity.is_suspicious(5000, 100, iso(30), NOW) is True

    def test_clearly_fine(self):
        assert popularity.is_suspicious(500, 200, iso(1000), NOW) is False

    def test_fails_only_stars_condition(self):
        assert popularity.is_suspicious(1000, 10, iso(30), NOW) is False

    def test_fails_only_age_condition(self):
        assert popularity.is_suspicious(5000, 50, iso(400), NOW) is False

    def test_fails_only_fork_ratio_condition(self):
        assert popularity.is_suspicious(5000, 700, iso(30), NOW) is False

    def test_all_three_barely_over_threshold(self):
        assert popularity.is_suspicious(3001, 1, iso(179), NOW) is True

    def test_boundary_stars_exactly_at_threshold_not_flagged(self):
        # stars > 3000 is strict; == 3000 must not flag.
        assert popularity.is_suspicious(3000, 1, iso(30), NOW) is False

    def test_boundary_age_exactly_at_threshold_not_flagged(self):
        # age < 180 is strict; == 180 must not flag.
        assert popularity.is_suspicious(5000, 1, iso(180), NOW) is False

    def test_boundary_fork_ratio_exactly_at_threshold_not_flagged(self):
        # forks/stars < 0.12 is strict; == 0.12 must not flag.
        assert popularity.is_suspicious(10000, 1200, iso(30), NOW) is False

    def test_zero_stars_never_flagged(self):
        assert popularity.is_suspicious(0, 0, iso(1), NOW) is False


class TestForkRatio:
    def test_normal(self):
        assert popularity.fork_ratio(100, 1000) == pytest.approx(0.1)

    def test_zero_stars_is_zero_not_division_error(self):
        assert popularity.fork_ratio(0, 0) == 0.0


class TestAgeDays:
    def test_basic(self):
        assert popularity.age_days(iso(45), NOW) == 45


class TestParseIso:
    def test_plain_z_form(self):
        assert popularity.parse_iso("2024-01-01T00:00:00Z").year == 2024

    def test_offset_form(self):
        assert popularity.parse_iso("2024-01-01T00:00:00+00:00").year == 2024

    def test_fractional_seconds_from_the_registry(self):
        # The MCP Registry emits microsecond precision; the original strptime
        # form raised on it, which would have taken down a whole audit.
        assert popularity.parse_iso("2026-05-05T14:01:01.659721Z").month == 5

    def test_garbage_raises_valueerror(self):
        with pytest.raises(ValueError):
            popularity.parse_iso("not a timestamp")


class TestAssess:
    def test_flagged_repo_produces_one_low_confidence_finding(self):
        assessment, findings = popularity.assess(make_meta(5000, 50, 30), now=NOW)
        assert assessment.severity is Severity.MEDIUM
        assert len(findings) == 1
        # The arithmetic is certain; what it implies is not.
        assert findings[0].confidence.value == "LOW"
        assert "3000" in findings[0].explanation

    def test_ordinary_repo_produces_no_findings(self):
        assessment, findings = popularity.assess(make_meta(100, 40, 900), now=NOW)
        assert assessment.severity is Severity.NOT_FLAGGED
        assert findings == []

    def test_summary_never_claims_safety(self):
        assessment, _ = popularity.assess(make_meta(100, 40, 900), now=NOW)
        assert "not the same as vetted" in assessment.summary.lower()
        assert "safe" not in assessment.summary.lower()
