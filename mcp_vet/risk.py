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
from .scanning import is_shipped

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


def finding_is_shipped(finding: Finding) -> bool:
    """Does this finding touch code that runs when the server runs?

    A finding whose every piece of evidence sits in tests, release scripts or
    documentation describes the repository, not the running server. It is still
    reported - suppression is not on the table, see the module docstring - but
    it must not set the headline.

    Auditing three widely-installed servers made the cost concrete: each
    produced a HIGH, and all three were a test file, an issue template and a
    release script. A verdict of "HIGH" on that basis teaches a reader to stop
    reading verdicts.

    Evidence with no path at all counts as shipped. Dropping a manifest-level
    observation out of the verdict would be a silent false negative, which is
    the error this tool cannot afford.
    """
    paths = [e.path for e in finding.evidence]
    if not paths:
        return True
    return any(is_shipped(p) for p in paths)


def finding_is_defensive(finding: Finding) -> bool:
    """Is every line behind this finding a refusal, or prose about one?

    Two shapes qualify, both decided in `scanning`: a mention inside a
    denylist literal, and a mention in a comment or docstring.

    The case that forced this: a notes server keeps

        SECRET_FILENAMES = {".env", ".netrc", "id_rsa", "credentials.json"}

    so those files are never indexed, and documents the refusal in the
    docstring of the function that enforces it. mcp-vet read both as
    "references SSH key material", rated the server HIGH, and printed DO NOT
    INSTALL. Rating the defensive pattern worse than its absence is an
    instruction to stop writing it.

    A finding with one piece of ordinary evidence is not defensive. One real
    `open("~/.ssh/id_rsa")` anywhere keeps the whole finding in the headline,
    however many denylists surround it - the asymmetry is the same one the
    rest of this module keeps: over-reporting is survivable.

    Evidence without a context - anything the scanner could not classify -
    counts as ordinary.
    """
    if not finding.evidence:
        return False
    return all(e.context in ("exclusion", "prose") for e in finding.evidence)


def finding_sets_headline(finding: Finding) -> bool:
    """May this finding decide the one number a reader acts on?

    The two qualifications compose, and they have to be applied per piece of
    evidence rather than per finding. A single finding often carries evidence
    from several places at once: the denylist in the server, the docstring
    that explains it, and the test that checks it. Judged finding-wide, each
    qualification sees at least one line it cannot vouch for and neither
    fires - so a server whose only mention of `.netrc` is a refusal to touch
    it still came out HIGH.

    A piece of evidence counts toward the headline when it is in shipped code
    **and** it is neither a denylist entry nor prose. One such line is enough:
    one real `open("~/.ssh/id_rsa")` keeps the finding in the verdict however
    many denylists surround it.

    A finding with no evidence at all still counts, as everywhere else here:
    dropping a manifest-level observation out of the verdict would be a silent
    false negative, and that is the error this tool cannot afford.
    """
    if not finding.evidence:
        return True
    for e in finding.evidence:
        if e.context in ("exclusion", "prose"):
            continue
        if e.path is None or is_shipped(e.path):
            return True
    return False


def overall_severity(findings: Sequence[Finding]) -> Severity:
    """The headline, decided by findings in shipped code only.

    Findings outside it keep their full severity everywhere else - in the
    findings list, in `area_severities`, in the JSON. Only this one number is
    scoped, because it is the one a reader acts on without reading further.
    """
    counts = [f for f in findings if finding_sets_headline(f)]
    return worst([_demoted(f.severity, f.confidence) for f in counts])


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

    for area, assessment in existing.items():
        note = _outside_verdict_note(area, report.findings)
        if note and note not in assessment.summary:
            assessment.summary = f"{assessment.summary} {note}".strip()

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


OUTSIDE_VERDICT_NOTE = (
    "None of it sets the overall verdict: every line is in a comment, a "
    "denylist, or code outside the shipped server."
)


def _outside_verdict_note(area: Area, findings: Sequence[Finding]) -> str:
    """Say so when an area's rating comes only from lines the headline ignores.

    Areas keep full severity on purpose (see `area_severities`). Without this
    note a reader saw "Installation HIGH" next to "OVERALL RISK MEDIUM" and had
    to open the finding to learn that the HIGH was a `pip install` in a
    comment.
    """
    in_area = [f for f in findings if f.area is area]
    if in_area and not any(finding_sets_headline(f) for f in in_area):
        return OUTSIDE_VERDICT_NOTE
    return ""


def _default_summary(area: Area, severity: Severity, findings: Sequence[Finding]) -> str:
    count = sum(1 for f in findings if f.area is area)
    if severity is Severity.NOT_FLAGGED:
        return "No findings from the checks that ran."
    plural = "s" if count != 1 else ""
    return f"{count} finding{plural}, worst {severity.value}."
