"""Dependencies and installation: the code that runs before you read anything."""
from __future__ import annotations

from mcp_vet import dependencies, install
from mcp_vet.audit import audit_directory
from mcp_vet.models import Area, Severity, Status
from mcp_vet.scanning import scan_tree

from helpers import fixture


class TestNpmManifest:
    def setup_method(self):
        self.result = scan_tree(fixture("install_hooks"))
        self.report = dependencies.analyze(self.result)

    def test_ecosystem_and_counts(self):
        assert self.report.ecosystem == "npm"
        assert self.report.direct_count == 3

    def test_install_hooks_are_captured_verbatim(self):
        assert set(self.report.install_scripts) == {"postinstall", "prepare"}
        assert "curl" in self.report.install_scripts["postinstall"]

    def test_git_dependency_is_flagged_as_non_registry(self):
        names = {name for name, _ in self.report.remote_sources}
        assert "internal-tools" in names

    def test_floating_ranges_are_counted(self):
        assert any(spec.startswith("left-pad@") for spec in self.report.unpinned)

    def test_missing_lockfile_is_stated(self):
        assert self.report.lockfile_path is None
        assert any("lockfile" in note for note in self.report.notes)

    def test_install_script_finding_is_high_and_quotes_the_command(self):
        findings = {f.rule_id: f for f in dependencies.findings_for(self.report, None)}
        finding = findings["dependencies.install_scripts"]
        assert finding.severity is Severity.HIGH
        assert finding.area is Area.INSTALLATION
        assert "curl" in finding.evidence[0].detail
        assert "--ignore-scripts" in finding.remediation


class TestNoManifest:
    def test_absent_manifest_is_not_applicable_rather_than_clean(self):
        report = dependencies.analyze(scan_tree(fixture("clean_server")))
        assert report.status is Status.NOT_APPLICABLE
        assert dependencies.findings_for(report, None) == []


class TestInstallScripts:
    def test_curl_pipe_shell_is_critical(self):
        findings = {f.rule_id: f for f in install.analyze(scan_tree(fixture("remote_pipe")))}
        finding = findings["install.remote_script_execution"]
        assert finding.severity is Severity.CRITICAL
        assert finding.evidence[0].path == "install.sh"

    def test_dockerfile_binary_download_is_flagged(self):
        findings = {f.rule_id: f for f in install.analyze(scan_tree(fixture("remote_pipe")))}
        assert "install.dockerfile_binary_download" in findings

    def test_clean_project_has_no_install_findings(self):
        assert install.analyze(scan_tree(fixture("clean_server"))) == []

    def test_setup_py_running_commands_is_flagged(self, tmp_path):
        (tmp_path / "setup.py").write_text(
            "import subprocess\nfrom setuptools import setup\n"
            "subprocess.run(['echo', 'hi'])\nsetup(name='x')\n"
        )
        findings = {f.rule_id: f for f in install.analyze(scan_tree(str(tmp_path)))}
        assert "install.setup_py_executes" in findings


class TestVulnerabilityHonesty:
    def test_report_never_claims_a_dependency_is_vulnerable(self):
        report = audit_directory(fixture("install_hooks"))
        assert report.notes["dependencies"]["vulnerability_status"] == "unavailable"
        blob = report.to_json().lower()
        assert "vulnerable" not in blob or "known-vulnerable" in blob
        assert any("vulnerability status unavailable" in lim.lower() for lim in report.limitations)
