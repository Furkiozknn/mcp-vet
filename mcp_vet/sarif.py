"""SARIF 2.1.0 output, so an audit can land in GitHub code scanning.

SARIF is a third view of the same `AuditReport`, next to the text report and
the JSON. It adds no opinion of its own: every result is one `Finding`, with
the same rule id, severity, confidence and evidence lines.

Three mapping decisions are worth knowing about.

**Severity becomes `level` and `security-severity`.** GitHub sorts and filters
code-scanning alerts by the numeric `security-severity` on the rule (9.0 and
up is critical, 7.0 high, 4.0 medium, below that low), and shows `level` as
error / warning / note. INFO findings carry no security-severity: they are
context, not vulnerabilities.

**A finding that does not set the verdict is a `note`.** mcp-vet reports a HIGH
that only sits in a test file or a denylist in full, but does not let it decide
the headline (`risk.finding_sets_headline`). In SARIF that becomes level `note`
with `properties.sets_verdict = false`, so the alert is still there for anyone
who looks, but a code-scanning gate on "error" does not fail on it - the same
answer the exit code gives.

**Every limitation is a tool notification.** "What this did not check" is
part of the report; dropping it from SARIF would turn a partial audit into a
clean-looking one. Limitations travel as `toolExecutionNotifications` on the
invocation, at level `warning`.

Findings without a file (repository metadata, registry provenance) have no
physical location. SARIF allows that; GitHub code scanning only shows results
with a file, so a CI job should audit with `--offline --path`, where every
finding comes from a file.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from . import __version__
from .models import AuditReport, Confidence, Evidence, Finding, Severity
from .risk import finding_sets_headline

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Furkiozknn/mcp-vet"

# GitHub's buckets: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
    Severity.NOT_FLAGGED: "none",
}

# SARIF's `precision` vocabulary, which GitHub reads from rule properties.
_PRECISION = {
    Confidence.HIGH: "high",
    Confidence.MEDIUM: "medium",
    Confidence.LOW: "low",
}


def _uri(path: str, prefix: str = "") -> str:
    """A path relative to the audited directory, as a URI relative to the checkout.

    Evidence paths are relative to `--path`. Code scanning resolves a URI
    against the root of the checkout, so auditing `--path server` from the
    repository root needs `server/` in front, or no alert lands on its file.
    """
    joined = path.replace("\\", "/").lstrip("/")
    if prefix:
        joined = prefix.rstrip("/") + "/" + joined
    return quote(joined, safe="/")


def path_prefix_for(audited: str, root: Optional[str] = None) -> str:
    """The audited directory relative to `root` (default: the working directory).

    Empty when the audited directory is the root itself or lies outside it;
    outside the checkout there is no prefix that would make the URI resolve.
    """
    root_abs = os.path.abspath(root or os.getcwd())
    rel = os.path.relpath(os.path.abspath(audited), root_abs)
    if rel == "." or rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return ""
    return rel.replace(os.sep, "/")


def _location(evidence: Evidence, prefix: str = "") -> Optional[Dict[str, Any]]:
    if not evidence.path:
        return None
    physical: Dict[str, Any] = {
        "artifactLocation": {"uri": _uri(evidence.path, prefix), "uriBaseId": "%SRCROOT%"},
    }
    if evidence.line:
        region: Dict[str, Any] = {"startLine": int(evidence.line)}
        if evidence.snippet:
            region["snippet"] = {"text": evidence.snippet}
        physical["region"] = region
    location: Dict[str, Any] = {"physicalLocation": physical}
    if evidence.detail:
        location["message"] = {"text": evidence.detail}
    return location


def _fingerprint(finding: Finding, location: Optional[Dict[str, Any]]) -> str:
    """Stable across runs for the same rule at the same place.

    Line numbers are left out on purpose: an unrelated edit above the line
    would otherwise turn one alert into "fixed" plus "new".
    """
    uri = ""
    snippet_text = ""
    if location:
        physical = location["physicalLocation"]
        uri = physical["artifactLocation"]["uri"]
        snippet_text = physical.get("region", {}).get("snippet", {}).get("text", "")
    material = "\x1f".join((finding.rule_id or finding.title, uri, snippet_text.strip()))
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:32]


def _rule(finding: Finding) -> Dict[str, Any]:
    properties: Dict[str, Any] = {
        "tags": ["security", "mcp", finding.area.value],
        "precision": _PRECISION[finding.confidence],
        "problem.severity": "error" if finding.severity in (Severity.CRITICAL, Severity.HIGH)
        else ("warning" if finding.severity in (Severity.MEDIUM, Severity.LOW) else "recommendation"),
    }
    if finding.severity in _SECURITY_SEVERITY:
        properties["security-severity"] = _SECURITY_SEVERITY[finding.severity]
    rule: Dict[str, Any] = {
        "id": finding.rule_id or finding.title,
        "name": (finding.rule_id or finding.title).replace(".", "_"),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.explanation},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": properties,
    }
    if finding.remediation:
        rule["help"] = {"text": finding.remediation}
    return rule


def _result(finding: Finding, rule_index: int, prefix: str = "") -> Dict[str, Any]:
    sets_verdict = finding_sets_headline(finding)
    locations = [loc for loc in (_location(e, prefix) for e in finding.evidence) if loc]
    level = _LEVEL[finding.severity] if sets_verdict else "note"
    message = finding.title
    if finding.remediation:
        message += f" - {finding.remediation}"
    result: Dict[str, Any] = {
        "ruleId": finding.rule_id or finding.title,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": message},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "area": finding.area.value,
            "sets_verdict": sets_verdict,
        },
    }
    if locations:
        result["locations"] = locations[:1]
        if len(locations) > 1:
            result["relatedLocations"] = [
                dict(loc, id=index) for index, loc in enumerate(locations[1:], start=1)
            ]
    else:
        # Evidence without a file (metadata, registry): kept in the text so it
        # is not lost, even though code scanning cannot pin it to a line.
        details = [e.detail for e in finding.evidence if e.detail]
        if details:
            result["message"]["text"] += " (" + "; ".join(details[:4]) + ")"
    result["partialFingerprints"] = {
        "mcpVetFinding/v1": _fingerprint(finding, locations[0] if locations else None),
    }
    return result


def to_sarif(report: AuditReport, path_prefix: str = "") -> Dict[str, Any]:
    """The whole report as one SARIF log with one run.

    `path_prefix` is prepended to every evidence path (see `path_prefix_for`).
    """
    rules: List[Dict[str, Any]] = []
    rule_index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []
    for finding in report.sorted_findings():
        key = finding.rule_id or finding.title
        if key not in rule_index:
            rule_index[key] = len(rules)
            rules.append(_rule(finding))
        results.append(_result(finding, rule_index[key], path_prefix))

    notifications = [
        {"level": "warning", "message": {"text": limitation}}
        for limitation in report.limitations
    ]
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "mcp-vet",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "automationDetails": {"id": f"mcp-vet/{report.target}/"},
        "invocations": [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": notifications,
            }
        ],
        "results": results,
        "properties": {
            "target": report.target,
            "overall": report.overall.value,
            "recommendation": report.recommendation,
            "report_schema_version": report.schema_version,
        },
    }
    if report.source_url:
        run["versionControlProvenance"] = [{"repositoryUri": report.source_url}]
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def render_sarif(report: AuditReport, path_prefix: str = "") -> str:
    return json.dumps(to_sarif(report, path_prefix), indent=2, ensure_ascii=False)
