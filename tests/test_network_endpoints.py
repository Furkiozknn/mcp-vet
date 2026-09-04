"""Network destination extraction and classification."""
from __future__ import annotations

from mcp_vet import network
from mcp_vet.models import EndpointClass, Severity
from mcp_vet.scanning import ScannedFile

from helpers import fixture


def scanned(text, path="server.py"):
    return ScannedFile(path=path, text=text, lines=text.splitlines(), size_bytes=len(text))


def hosts(text, purpose=""):
    return {e.host: e for e in network.extract_endpoints([scanned(text)], purpose)}


class TestClassification:
    def test_host_matching_the_purpose_is_expected(self):
        found = hosts('URL = "https://api.github.com/repos"', purpose="github issue management")
        assert found["api.github.com"].classification is EndpointClass.EXPECTED

    def test_unrelated_host_is_unexplained_not_suspicious(self):
        # mcp-vet cannot know every legitimate API, and saying "suspicious"
        # for every one it does not recognise would make the label worthless.
        found = hosts('URL = "https://api.weatherapi.com/v1"', purpose="github issue management")
        assert found["api.weatherapi.com"].classification is EndpointClass.UNEXPLAINED

    def test_package_registry_is_infrastructure(self):
        found = hosts('"https://registry.npmjs.org/left-pad"')
        assert found["registry.npmjs.org"].classification is EndpointClass.INFRASTRUCTURE

    def test_paste_service_is_suspicious(self):
        found = hosts('requests.post("https://pastebin.com/api/api_post.php", data=d)')
        assert found["pastebin.com"].classification is EndpointClass.SUSPICIOUS

    def test_webhook_catcher_is_suspicious(self):
        found = hosts('URL = "https://webhook.site/abc-123"')
        assert found["webhook.site"].classification is EndpointClass.SUSPICIOUS

    def test_raw_ip_literal_is_suspicious(self):
        found = hosts('URL = "http://203.0.113.9/collect"')
        assert found["203.0.113.9"].classification is EndpointClass.SUSPICIOUS

    def test_telemetry_is_unexplained_with_a_disclosure_note(self):
        found = hosts('URL = "https://api.mixpanel.com/track"')
        endpoint = found["api.mixpanel.com"]
        assert endpoint.classification is EndpointClass.UNEXPLAINED
        assert "opt-in" in endpoint.reason


class TestFindings:
    def test_suspicious_destination_produces_a_high_finding(self):
        endpoints = network.extract_endpoints([scanned('u = "https://pastebin.com/x"')])
        findings = {f.rule_id: f for f in network.findings_for(endpoints)}
        assert findings["network.suspicious_destination"].severity is Severity.HIGH

    def test_cleartext_http_is_flagged(self):
        endpoints = network.extract_endpoints([scanned('u = "http://api.example.org/v1"')])
        findings = {f.rule_id: f for f in network.findings_for(endpoints)}
        assert "network.cleartext_http" in findings

    def test_localhost_over_http_is_not_flagged(self):
        endpoints = network.extract_endpoints([scanned('u = "http://localhost:8080/x"')])
        assert network.findings_for(endpoints) == []

    def test_unexplained_alone_produces_no_finding(self):
        # Otherwise every legitimate server would carry a finding for its own API.
        endpoints = network.extract_endpoints([scanned('u = "https://api.open-meteo.com/v1"')])
        assert network.findings_for(endpoints) == []

    def test_ordering_puts_suspicious_first(self):
        text = 'a="https://registry.npmjs.org/x"\nb="https://pastebin.com/y"\n'
        endpoints = network.extract_endpoints([scanned(text)])
        assert endpoints[0].classification is EndpointClass.SUSPICIOUS
