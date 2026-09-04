"""Where a server can send data, and whether that fits what it claims to do.

"Makes HTTP requests" tells a reader nothing. Every useful server does. The
question worth answering is *which hosts*, and whether each one has any
apparent relationship to the server's stated purpose. A GitHub MCP server
talking to api.github.com is the tool working; the same server also posting to
an unfamiliar host is the finding.

Unknown is not the same as malicious, and this module refuses to conflate them.
A destination is EXPECTED, INFRASTRUCTURE, UNEXPLAINED or SUSPICIOUS - and
UNEXPLAINED is by far the most common verdict for a legitimate server, because
mcp-vet cannot know that `api.weatherapi.com` is exactly what a weather server
should be calling. It says "this is here, it did not obviously follow from the
description, look at it".
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Set

from .models import (
    Area,
    Confidence,
    EndpointClass,
    Evidence,
    Finding,
    NetworkEndpoint,
    Severity,
)
from .scanning import ScannedFile, snippet

_URL_RE = re.compile(r"(https?)://([A-Za-z0-9._~-]+)(?::(\d+))?")

# Hosts that are part of building or documenting software rather than part of
# what the server does at runtime. Present in almost every repository.
_INFRASTRUCTURE = {
    "registry.npmjs.org", "npmjs.com", "www.npmjs.com", "pypi.org", "files.pythonhosted.org",
    "crates.io", "proxy.golang.org", "sum.golang.org", "rubygems.org", "packagist.org",
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "codeload.github.com",
    "schemas.modelcontextprotocol.io", "static.modelcontextprotocol.io",
    "modelcontextprotocol.io", "spdx.org", "json-schema.org", "www.w3.org",
    "opensource.org", "creativecommons.org", "img.shields.io", "shields.io",
    "localhost", "127.0.0.1", "0.0.0.0", "example.com", "www.example.com",
    "example.org", "example.net", "docs.python.org", "nodejs.org", "developer.mozilla.org",
}

# Destinations whose presence is a finding on its own, whatever the purpose.
_SUSPICIOUS_HOSTS = {
    # Paste and tunnel services: exfiltration destinations that need no setup.
    "pastebin.com", "hastebin.com", "paste.ee", "ghostbin.com", "transfer.sh",
    "0x0.st", "file.io", "anonfiles.com", "termbin.com",
    "ngrok.io", "trycloudflare.com", "loca.lt", "serveo.net",
    # Webhook catchers, used to receive stolen data during development.
    "webhook.site", "requestbin.com", "pipedream.net", "requestcatcher.com",
    "beeceptor.com", "interact.sh", "oast.fun", "burpcollaborator.net",
    "canarytokens.com",
}

# Telemetry, which is not malicious but is a data flow a user should consent to.
_TELEMETRY_HOSTS = {
    "google-analytics.com", "www.google-analytics.com", "analytics.google.com",
    "sentry.io", "ingest.sentry.io", "segment.io", "api.segment.io",
    "mixpanel.com", "api.mixpanel.com", "amplitude.com", "api.amplitude.com",
    "posthog.com", "app.posthog.com", "bugsnag.com", "datadoghq.com",
}

# A raw IPv4 literal as a destination. Legitimate code names hosts.
_IP_LITERAL = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _tokens(text: str) -> Set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) > 2}


def _registrable(host: str) -> str:
    """A rough 'name' for a host: the label before the public suffix.

    Not a real public-suffix-list implementation - it does not need to be. It
    exists so `api.github.com` and `github.com` both read as "github" when
    matching against a description.
    """
    parts = host.lower().split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else host


def classify(host: str, purpose_tokens: Set[str]) -> tuple:
    """Return (EndpointClass, reason) for one host."""
    lowered = host.lower()
    if lowered in _SUSPICIOUS_HOSTS:
        return (
            EndpointClass.SUSPICIOUS,
            "Paste, tunnel or webhook-capture service - a destination whose purpose is "
            "to receive arbitrary data from somewhere else.",
        )
    if lowered in _TELEMETRY_HOSTS:
        return (
            EndpointClass.UNEXPLAINED,
            "Analytics or error-reporting service. Not an attack, but it is a data flow "
            "off your machine that should be disclosed and ideally opt-in.",
        )
    if _IP_LITERAL.match(lowered):
        return (
            EndpointClass.SUSPICIOUS,
            "Hard-coded IP address rather than a hostname. Legitimate services are named; "
            "a bare address avoids DNS records anyone could look up.",
        )
    if lowered in _INFRASTRUCTURE:
        return (
            EndpointClass.INFRASTRUCTURE,
            "Package registry, source host or documentation - build-time rather than a "
            "runtime data destination.",
        )
    name = _registrable(lowered)
    if name in purpose_tokens:
        return (
            EndpointClass.EXPECTED,
            f"'{name}' appears in the server's own name or description, so this "
            "destination follows from what it says it does.",
        )
    return (
        EndpointClass.UNEXPLAINED,
        "No obvious relationship to the server's stated purpose. Most often benign - "
        "mcp-vet cannot know every legitimate API - but worth one look.",
    )


def extract_endpoints(
    files: Sequence[ScannedFile],
    purpose: str = "",
) -> List[NetworkEndpoint]:
    """Collect every literal URL host in the tree and classify each one."""
    purpose_tokens = _tokens(purpose)
    seen: Dict[str, NetworkEndpoint] = {}
    counts: Dict[str, int] = defaultdict(int)

    for scanned in files:
        for index, line in enumerate(scanned.lines, start=1):
            if len(line) > 4000:
                continue
            for match in _URL_RE.finditer(line):
                scheme, host = match.group(1), match.group(2).lower().rstrip(".")
                if not host or "." not in host and host not in {"localhost"}:
                    continue
                counts[host] += 1
                if host in seen:
                    continue
                classification, reason = classify(host, purpose_tokens)
                endpoint = NetworkEndpoint(
                    host=host,
                    scheme=scheme,
                    classification=classification,
                    reason=reason,
                    evidence=[Evidence(path=scanned.path, line=index, snippet=snippet(line))],
                )
                # http:// to a non-local host means credentials and payloads
                # cross the network in cleartext.
                if scheme == "http" and host not in {"localhost", "127.0.0.1", "0.0.0.0"}:
                    endpoint.reason += " Uses plain http, so anything sent is readable in transit."
                seen[host] = endpoint

    ordering = {
        EndpointClass.SUSPICIOUS: 0,
        EndpointClass.UNEXPLAINED: 1,
        EndpointClass.EXPECTED: 2,
        EndpointClass.INFRASTRUCTURE: 3,
    }
    return sorted(seen.values(), key=lambda e: (ordering[e.classification], e.host))


def findings_for(endpoints: Sequence[NetworkEndpoint]) -> List[Finding]:
    suspicious = [e for e in endpoints if e.classification is EndpointClass.SUSPICIOUS]
    findings: List[Finding] = []

    if suspicious:
        findings.append(
            Finding(
                rule_id="network.suspicious_destination",
                area=Area.NETWORK,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title="Contacts a paste, tunnel, webhook-capture or raw-IP destination",
                explanation=(
                    "These hosts exist to receive data from elsewhere, or avoid being "
                    "named at all. Hosts: "
                    + ", ".join(e.host for e in suspicious[:6])
                    + ". A server doing legitimate work generally talks to a documented "
                    "API under its own domain."
                ),
                evidence=[ev for e in suspicious[:3] for ev in e.evidence[:1]],
                remediation=(
                    "Find the call site and establish what is sent there. Treat this as "
                    "disqualifying unless the repository explains it convincingly."
                ),
            )
        )

    cleartext = [
        e for e in endpoints
        if e.scheme == "http" and e.host not in {"localhost", "127.0.0.1", "0.0.0.0"}
        and e.classification is not EndpointClass.INFRASTRUCTURE
    ]
    if cleartext:
        findings.append(
            Finding(
                rule_id="network.cleartext_http",
                area=Area.NETWORK,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title="Sends traffic over plain http to a non-local host",
                explanation=(
                    "Anything sent this way - including credentials - is readable and "
                    "modifiable by anything on the network path. Hosts: "
                    + ", ".join(e.host for e in cleartext[:6])
                    + "."
                ),
                evidence=[ev for e in cleartext[:3] for ev in e.evidence[:1]],
                remediation="Require https, or do not send credentials over this connection.",
            )
        )

    return findings
