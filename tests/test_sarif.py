"""SARIF 2.1.0 output: a third view of the same report, not a new opinion."""
from __future__ import annotations

import json

import pytest

from mcp_vet import risk
from mcp_vet.audit import audit_directory
from mcp_vet.cli import main
from mcp_vet.models import Area, AuditReport, Confidence, Evidence, Finding, Severity
from mcp_vet.sarif import to_sarif

from helpers import fixture


def _sarif_from_cli(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr().out
    return code, json.loads(out)


def _finding(severity=Severity.HIGH, path="server.py", line=3, snippet="x = 1",
             context=None, rule_id="source.example", confidence=Confidence.HIGH):
    evidence = [Evidence(path=path, line=line, snippet=snippet, context=context)] if path else []
    return Finding(area=Area.SOURCE_CODE, severity=severity, confidence=confidence,
                   title="Example", explanation="Why it matters.", evidence=evidence,
                   remediation="Look at it.", rule_id=rule_id)


class TestShape:
    def test_poisoned_fixture_is_a_valid_looking_sarif_log(self, capsys):
        code, log = _sarif_from_cli(capsys, "audit", "--offline", "--path",
                                    fixture("poisoned_server"), "--sarif")
        assert log["version"] == "2.1.0"
        assert "sarif-2.1.0" in log["$schema"]
        assert len(log["runs"]) == 1
        run = log["runs"][0]
        assert run["tool"]["driver"]["name"] == "mcp-vet"
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids)), "each rule is declared once"
        for result in run["results"]:
            assert result["ruleId"] in rule_ids
            assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
            assert result["level"] in ("error", "warning", "note", "none")

    def test_one_result_per_finding_and_same_exit_code(self, capsys):
        path = fixture("poisoned_server")
        report = audit_directory(path, target=path)
        code, log = _sarif_from_cli(capsys, "audit", "--offline", "--path", path, "--sarif")
        assert len(log["runs"][0]["results"]) == len(report.findings)
        assert code == risk.exit_code_for(report.overall) == 3

    def test_results_point_at_the_file_and_line_of_the_evidence(self, capsys):
        _, log = _sarif_from_cli(capsys, "audit", "--offline", "--path",
                                 fixture("poisoned_server"), "--sarif")
        located = [r for r in log["runs"][0]["results"] if "locations" in r]
        assert located
        for result in located:
            physical = result["locations"][0]["physicalLocation"]
            assert physical["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
            uri = physical["artifactLocation"]["uri"]
            assert not uri.startswith("/") and "\\" not in uri
        assert any(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "server.py"
            and r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
            for r in located
        )

    def test_report_command_emits_sarif_too(self, capsys):
        code, log = _sarif_from_cli(capsys, "report", "--offline", "--path",
                                    fixture("exfil_server"), "--sarif")
        assert log["version"] == "2.1.0"
        assert code == 2

    def test_sarif_and_json_together_is_a_usage_error(self, capsys):
        # A usage error exits 4, never 2 (HIGH): see cli._Parser.
        with pytest.raises(SystemExit) as exc:
            main(["audit", "--offline", "--path", fixture("clean_server"), "--json", "--sarif"])
        assert exc.value.code == risk.EXIT_ERROR

    def test_sarif_and_text_together_is_a_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["report", "--offline", "--path", fixture("clean_server"), "--text", "--sarif"])
        assert exc.value.code == risk.EXIT_ERROR

    def test_a_missing_path_still_exits_four_with_sarif(self, capsys):
        assert main(["audit", "--offline", "--path", "does-not-exist-xyz", "--sarif"]) == risk.EXIT_ERROR


class TestSeverityMapping:
    def test_critical_maps_to_error_and_github_critical_bucket(self):
        log = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(Severity.CRITICAL)])))
        rule = log["runs"][0]["tool"]["driver"]["rules"][0]
        assert float(rule["properties"]["security-severity"]) >= 9.0
        assert log["runs"][0]["results"][0]["level"] == "error"

    def test_medium_is_a_warning_in_the_github_medium_bucket(self):
        log = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(Severity.MEDIUM)])))
        rule = log["runs"][0]["tool"]["driver"]["rules"][0]
        assert 4.0 <= float(rule["properties"]["security-severity"]) < 7.0
        assert log["runs"][0]["results"][0]["level"] == "warning"

    def test_info_has_no_security_severity(self):
        log = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(Severity.INFO)])))
        rule = log["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security-severity" not in rule["properties"]
        assert log["runs"][0]["results"][0]["level"] == "note"

    def test_confidence_travels_as_precision(self):
        log = to_sarif(risk.finalize(AuditReport(
            target="t", findings=[_finding(confidence=Confidence.LOW)])))
        assert log["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["precision"] == "low"
        assert log["runs"][0]["results"][0]["properties"]["confidence"] == "LOW"


class TestVerdictAgreement:
    def test_a_high_only_in_tests_is_a_note_that_does_not_set_the_verdict(self):
        report = risk.finalize(AuditReport(
            target="t", findings=[_finding(Severity.HIGH, path="tests/test_x.py")]))
        result = to_sarif(report)["runs"][0]["results"][0]
        assert result["level"] == "note"
        assert result["properties"]["sets_verdict"] is False
        assert result["properties"]["severity"] == "HIGH"   # reported in full
        assert report.overall is Severity.NOT_FLAGGED

    def test_a_high_only_in_a_denylist_is_a_note(self):
        report = risk.finalize(AuditReport(
            target="t", findings=[_finding(Severity.HIGH, context="exclusion")]))
        assert to_sarif(report)["runs"][0]["results"][0]["level"] == "note"

    def test_a_high_in_shipped_code_is_an_error(self):
        report = risk.finalize(AuditReport(target="t", findings=[_finding(Severity.HIGH)]))
        result = to_sarif(report)["runs"][0]["results"][0]
        assert result["level"] == "error"
        assert result["properties"]["sets_verdict"] is True


class TestNothingIsDropped:
    def test_limitations_become_tool_notifications(self, capsys):
        path = fixture("clean_server")
        report = audit_directory(path, target=path)
        _, log = _sarif_from_cli(capsys, "audit", "--offline", "--path", path, "--sarif")
        notes = log["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert [n["message"]["text"] for n in notes] == report.limitations
        assert all(n["level"] == "warning" for n in notes)

    def test_every_evidence_line_is_kept(self):
        finding = _finding()
        finding.evidence.append(Evidence(path="other.py", line=9, snippet="y = 2"))
        result = to_sarif(risk.finalize(AuditReport(target="t", findings=[finding])))["runs"][0]["results"][0]
        assert len(result["locations"]) == 1
        related = result["relatedLocations"]
        assert related[0]["physicalLocation"]["artifactLocation"]["uri"] == "other.py"
        assert related[0]["id"] == 1

    def test_a_finding_without_a_file_keeps_its_detail_in_the_message(self):
        finding = Finding(area=Area.REPOSITORY_TRUST, severity=Severity.MEDIUM,
                          confidence=Confidence.HIGH, title="Repository is archived",
                          explanation="e", evidence=[Evidence(detail="archived=true on a/b")],
                          rule_id="trust.archived")
        result = to_sarif(risk.finalize(AuditReport(target="a/b", findings=[finding])))["runs"][0]["results"][0]
        assert "locations" not in result
        assert "archived=true on a/b" in result["message"]["text"]

    def test_overall_verdict_is_in_run_properties(self, capsys):
        _, log = _sarif_from_cli(capsys, "audit", "--offline", "--path",
                                 fixture("poisoned_server"), "--sarif")
        assert log["runs"][0]["properties"]["overall"] == "CRITICAL"


class TestFingerprints:
    def test_fingerprint_survives_a_line_shift(self):
        a = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(line=3)])))
        b = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(line=40)])))
        fa = a["runs"][0]["results"][0]["partialFingerprints"]
        fb = b["runs"][0]["results"][0]["partialFingerprints"]
        assert fa == fb

    def test_fingerprint_differs_for_a_different_file(self):
        a = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(path="a.py")])))
        b = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(path="b.py")])))
        assert (a["runs"][0]["results"][0]["partialFingerprints"]
                != b["runs"][0]["results"][0]["partialFingerprints"])

    def test_output_is_byte_stable(self, capsys):
        main(["audit", "--offline", "--path", fixture("exfil_server"), "--sarif"])
        first = capsys.readouterr().out
        main(["audit", "--offline", "--path", fixture("exfil_server"), "--sarif"])
        assert capsys.readouterr().out == first


def test_paths_with_spaces_are_uri_encoded():
    log = to_sarif(risk.finalize(AuditReport(target="t", findings=[_finding(path="src/my server.py")])))
    uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/my%20server.py"
