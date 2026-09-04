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
