"""Turning findings into a verdict, without pretending to a number.

The rule this module exists to enforce: **no single score**. A server can be
impeccably maintained, widely starred, and still read your environment and post
it somewhere. Averaging those into one figure destroys exactly the information
a reader needs, so each area keeps its own severity and the overall verdict is
the worst of them, not the mean of them.

Confidence is applied here rather than at detection time. A finding is always
*reported* at its true severity - suppressing a HIGH because the tool is unsure
would be the wrong trade in a security context - but a LOW-confidence finding
contributes one notch lower to the overall verdict, so a single speculative
regex match cannot on its own produce a CRITICAL headline.
"""
from __future__ import annotations

from typing import Dict, List, Sequence

from .models import Area, AreaAssessment, AuditReport, Confidence, Finding, Severity, Status

_ORDER = [
    Severity.NOT_FLAGGED,
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

# What the CLI exits with. Documented in README and docs/json-schema.md, and
# stable: CI gates depend on these.
EXIT_CLEAN = 0        # nothing above INFO
EXIT_WARNINGS = 1     # LOW or MEDIUM
EXIT_HIGH = 2         # HIGH
EXIT_CRITICAL = 3     # CRITICAL
EXIT_ERROR = 4        # mcp-vet itself could not complete

_RECOMMENDATIONS = {
    Severity.CRITICAL: (
        "DO NOT INSTALL. At least one critical finding stands; treat this server as "
        "hostile until each one is explained by the author."
    ),
    Severity.HIGH: (
        "DO NOT INSTALL WITHOUT MANUAL REVIEW. Open the files cited in the findings "
        "above and decide for yourself before this runs on your machine."
    ),
    Severity.MEDIUM: (
        "REVIEW BEFORE INSTALLING. Nothing here is disqualifying on its own, but the "
        "findings describe real capability worth understanding first."
    ),
    Severity.LOW: (
        "PROCEED WITH ORDINARY CARE. Minor findings only - read the source anyway, "
        "because a clean scan is not a review."
    ),
    Severity.INFO: (
        "NOT FLAGGED by these checks. That is not the same as safe: mcp-vet matches "
        "known patterns and cannot prove the absence of a problem. Read the source."
    ),
    Severity.NOT_FLAGGED: (
        "NOT FLAGGED by these checks. That is not the same as safe: mcp-vet matches "
        "known patterns and cannot prove the absence of a problem. Read the source."
    ),
}

# Stated on every report, whatever the verdict. A tool that only lists its
# limitations when it finds nothing is managing expectations, not disclosing.
STANDING_LIMITATIONS = [
    "No static analyzer can prove an MCP server is safe. mcp-vet matches known "
    "patterns; novel or deliberately obfuscated behaviour can pass it.",
    "Data-flow findings report that a sensitive read and an outbound call sit near "
    "each other in one file. That is co-location, not proven taint.",
    "Only the repository is examined. What a published package or a remote endpoint "
    "actually serves can differ from this source.",
    "Dependencies are enumerated, not audited. Vulnerability status is unavailable "
    "unless an advisory source was reachable and said otherwise.",
]


def _demoted(severity: Severity, confidence: Confidence) -> Severity:
    """A LOW-confidence finding counts one notch lower toward the headline."""
    if confidence is not Confidence.LOW:
        return severity
    return _ORDER[max(0, _ORDER.index(severity) - 1)]


def worst(severities: Sequence[Severity]) -> Severity:
    return max(severities, key=lambda s: _ORDER.index(s)) if severities else Severity.NOT_FLAGGED


def overall_severity(findings: Sequence[Finding]) -> Severity:
    return worst([_demoted(f.severity, f.confidence) for f in findings])


def area_severities(findings: Sequence[Finding]) -> Dict[Area, Severity]:
    """Highest severity seen per area, at full weight - areas are not headlines."""
    result: Dict[Area, Severity] = {}
    for finding in findings:
        current = result.get(finding.area, Severity.NOT_FLAGGED)
        result[finding.area] = worst([current, finding.severity])
    return result


def recommendation_for(severity: Severity) -> str:
    return _RECOMMENDATIONS[severity]


def exit_code_for(severity: Severity) -> int:
    if severity is Severity.CRITICAL:
        return EXIT_CRITICAL
    if severity is Severity.HIGH:
        return EXIT_HIGH
    if severity in (Severity.MEDIUM, Severity.LOW):
        return EXIT_WARNINGS
    return EXIT_CLEAN


def finalize(report: AuditReport) -> AuditReport:
    """Fill in overall severity, per-area rows and the recommendation.

    Areas that produced findings take their worst severity. Areas that ran and
    found nothing say so. Areas that could not run keep whatever status the
    analyzer gave them, so "could not check" never reads as "clean".
    """
    by_area = area_severities(report.findings)

    existing = {assessment.area: assessment for assessment in report.areas}
    for area, severity in by_area.items():
        if area in existing:
            # An analyzer's own summary wins on wording; the findings win on
            # severity, since they are the evidence.
            existing[area].severity = worst([existing[area].severity, severity])
        else:
            existing[area] = AreaAssessment(
                area=area,
                severity=severity,
                status=Status.VERIFIED,
                summary=_default_summary(area, severity, report.findings),
            )

    report.areas = [existing[a] for a in Area if a in existing]
    report.overall = overall_severity(report.findings)
    report.recommendation = recommendation_for(report.overall)

    for limitation in STANDING_LIMITATIONS:
        if limitation not in report.limitations:
            report.limitations.append(limitation)

    # Analyzers add their own caveats and some overlap with the standing set;
    # a reader should not be told the same thing twice in one block.
    report.limitations = _dedupe_preserving_order(report.limitations)
    return report


def _dedupe_preserving_order(items: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        key = item.strip().lower().rstrip(".")
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _default_summary(area: Area, severity: Severity, findings: Sequence[Finding]) -> str:
    count = sum(1 for f in findings if f.area is area)
    if severity is Severity.NOT_FLAGGED:
        return "No findings from the checks that ran."
    plural = "s" if count != 1 else ""
    return f"{count} finding{plural}, worst {severity.value}."
