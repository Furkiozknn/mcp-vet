"""Source analysis: capabilities, credentials, data flows, combinations.

The single most important assertion in this file is the one about the benign
fixture. A scanner that flags a clean weather server teaches its users to
ignore it, and an ignored scanner catches nothing - so "clean stays clean" is
tested as strictly as "malicious gets caught".
"""
from __future__ import annotations

from mcp_vet import source
from mcp_vet.audit import audit_directory
from mcp_vet.models import Confidence, Severity
from mcp_vet.scanning import scan_tree, source_files

from helpers import fixture


def analyze(name):
    result = scan_tree(fixture(name))
    files = source_files(result)
    matches = source.scan_matches(files)
    return result, files, matches


class TestCleanServerStaysClean:
    def test_no_findings_at_all(self):
        _, _, matches = analyze("clean_server")
        findings = source.matches_to_findings(matches)
        assert findings == [], f"false positives: {[f.rule_id for f in findings]}"

    def test_no_credentials_invented(self):
        _, files, _ = analyze("clean_server")
        assert source.extract_credentials(files) == []

    def test_no_dataflows(self):
        _, _, matches = analyze("clean_server")
        assert source.detect_dataflows(matches) == []

    def test_still_reports_the_capability_it_has(self):
        # Silence about findings must not mean silence about capability: the
        # server does make outbound requests and the report should say so.
        _, _, matches = analyze("clean_server")
        names = {c.name for c in source.matches_to_capabilities(matches)}
        assert names == {"network.external"}

    def test_overall_verdict_is_not_flagged_and_exits_zero(self):
        report = audit_directory(fixture("clean_server"))
        assert report.overall is Severity.NOT_FLAGGED
        assert "not the same as safe" in report.recommendation.lower()


class TestShellExecution:
    def test_shell_true_is_high_and_confident(self):
        _, _, matches = analyze("exfil_server")
        findings = {f.rule_id: f for f in source.matches_to_findings(matches)}
        finding = findings["source.shell_true"]
        assert finding.severity is Severity.HIGH
        assert finding.confidence is Confidence.HIGH
        assert finding.evidence[0].line > 0
        assert finding.evidence[0].path.endswith("server.py")

    def test_capability_is_recorded(self):
        _, _, matches = analyze("exfil_server")
        names = {c.name for c in source.matches_to_capabilities(matches)}
        assert "shell.execute" in names
        assert "process.spawn" in names


class TestCredentials:
    def test_names_are_found_with_required_flag(self):
        _, files, _ = analyze("exfil_server")
        creds = {c.name: c for c in source.extract_credentials(files)}
        assert set(creds) == {"GITHUB_TOKEN", "OPENAI_API_KEY"}
        # A bare subscript raises when absent; .get() does not.
        assert creds["GITHUB_TOKEN"].required is True
        assert creds["OPENAI_API_KEY"].required is False

    def test_blast_radius_is_specific_where_known(self):
        _, files, _ = analyze("exfil_server")
        creds = {c.name: c for c in source.extract_credentials(files)}
        assert "repositor" in creds["GITHUB_TOKEN"].blast_radius.lower()

    def test_no_credential_value_is_ever_captured(self):
        # The type has nowhere to put a value, and the evidence is one line of
        # source. This guards against a future change that starts resolving them.
        _, files, _ = analyze("exfil_server")
        for cred in source.extract_credentials(files):
            assert not hasattr(cred, "value")
            for ev in cred.evidence:
                assert "os.environ" in ev.snippet or "getenv" in ev.snippet


class TestDataFlow:
    def test_env_to_http_chain_resolves_the_destination(self):
        _, _, matches = analyze("exfil_server")
        flows = source.detect_dataflows(matches)
        network = [f for f in flows if f.sink == "network.external"]
        assert len(network) == 1
        assert network[0].source == "environment.read"
        assert network[0].destination == "telemetry-collect.example.net"

    def test_non_network_sinks_carry_no_destination(self):
        # Attaching the nearest URL to a subprocess call would assert something
        # that was never observed.
        _, _, matches = analyze("exfil_server")
        for flow in source.detect_dataflows(matches):
            if flow.sink not in {"network.external", "network.socket", "network.dns"}:
                assert flow.destination is None

    def test_confidence_never_exceeds_medium(self):
        # Proximity is not taint, and the report must not imply otherwise.
        _, _, matches = analyze("exfil_server")
        findings = source.dataflow_findings(source.detect_dataflows(matches))
        assert findings
        for finding in findings:
            assert finding.confidence is not Confidence.HIGH

    def test_exfil_finding_says_it_cannot_prove_taint(self):
        _, _, matches = analyze("exfil_server")
        findings = source.dataflow_findings(source.detect_dataflows(matches))
        assert any("cannot prove" in f.explanation for f in findings)


class TestObfuscation:
    def test_decode_plus_execute_is_critical(self):
        _, _, matches = analyze("obfuscated")
        combos = {f.rule_id: f for f in source.combination_findings(matches)}
        assert "combo.decode_then_execute" in combos
        assert combos["combo.decode_then_execute"].severity is Severity.CRITICAL

    def test_base64_alone_is_not_a_finding(self):
        # Decoding base64 is ordinary; only decode-then-execute is the shape.
        from mcp_vet.scanning import ScannedFile

        text = "import base64\nblob = base64.b64decode('aGk=')\nprint(blob)\n"
        scanned = ScannedFile(path="x.py", text=text, lines=text.splitlines(), size_bytes=len(text))
        matches = source.scan_matches([scanned])
        assert source.matches_to_findings(matches) == []
        assert source.combination_findings(matches) == []
