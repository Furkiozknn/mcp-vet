"""Repository trust and maintenance, beyond the popularity numbers.

Popularity says how many people looked. These signals say whether anyone is
still home: is it archived, is it a fork, has anyone pushed this year, is there
a licence, does more than one person contribute. None is decisive on its own -
a one-maintainer project can be excellent and a busy one can be abandoned
tomorrow - so they are reported as findings with their evidence rather than
folded into a score.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .github import RepoExtras, RepoMeta
from .models import (
    Area,
    AreaAssessment,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Status,
)
from .popularity import STALE_DAYS, parse_iso

SINGLE_MAINTAINER_THRESHOLD = 2
VERY_YOUNG_DAYS = 30


def assess(
    meta: RepoMeta,
    extras: Optional[RepoExtras] = None,
    now: Optional[datetime] = None,
) -> Tuple[AreaAssessment, AreaAssessment, List[Finding]]:
    """Return (repository trust, maintenance, findings)."""
    now = now or datetime.now(timezone.utc)
    findings: List[Finding] = []
    trust_severity = Severity.NOT_FLAGGED
    maintenance_severity = Severity.NOT_FLAGGED

    days_since_push = (now - parse_iso(meta.pushed_at)).days
    age = (now - parse_iso(meta.created_at)).days

    if meta.archived:
        maintenance_severity = Severity.MEDIUM
        findings.append(
            Finding(
                rule_id="trust.archived",
                area=Area.MAINTENANCE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Repository is archived",
                explanation=(
                    "The owner has marked this read-only. No fix will ship for any bug "
                    "or vulnerability found from here on, including one found in this audit."
                ),
                evidence=[Evidence(detail=f"archived=true on {meta.full_name}")],
                remediation="Prefer a maintained alternative, or plan to vendor and maintain it yourself.",
            )
        )

    if meta.disabled:
        trust_severity = Severity.HIGH
        findings.append(
            Finding(
                rule_id="trust.disabled",
                area=Area.REPOSITORY_TRUST,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Repository is disabled",
                explanation="GitHub has disabled this repository, which usually follows a policy action.",
                evidence=[Evidence(detail=f"disabled=true on {meta.full_name}")],
                remediation="Do not install. Find out why it was disabled first.",
            )
        )

    if days_since_push > STALE_DAYS and not meta.archived:
        maintenance_severity = max(maintenance_severity, Severity.LOW, key=lambda s: s.rank)
        findings.append(
            Finding(
                rule_id="trust.stale",
                area=Area.MAINTENANCE,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title=f"No commits in {days_since_push} days",
                explanation=(
                    "MCP is moving quickly enough that a server untouched for this long "
                    "may target an older protocol revision. Not a security finding by "
                    "itself, but it bears on whether anyone would respond to one."
                ),
                evidence=[Evidence(detail=f"last push {meta.pushed_at[:10]}")],
            )
        )

    if meta.license is None:
        trust_severity = max(trust_severity, Severity.LOW, key=lambda s: s.rank)
        findings.append(
            Finding(
                rule_id="trust.no_license",
                area=Area.REPOSITORY_TRUST,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="No licence on file",
                explanation=(
                    "Without a licence the default is exclusive copyright: you have no "
                    "granted right to use, modify or redistribute it. A legal problem "
                    "rather than a safety one, but a real one for anything shipped."
                ),
                evidence=[Evidence(detail="license=null in the GitHub API response")],
                remediation="Ask the author to add a licence before depending on this.",
            )
        )

    if meta.is_fork:
        trust_severity = max(trust_severity, Severity.LOW, key=lambda s: s.rank)
        findings.append(
            Finding(
                rule_id="trust.is_fork",
                area=Area.REPOSITORY_TRUST,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Repository is a fork",
                explanation=(
                    "A fork may carry changes the upstream project never reviewed. "
                    "Typosquatting an established server usually starts as a fork, so "
                    "compare the diff against upstream before trusting this copy."
                ),
                evidence=[Evidence(detail=f"fork=true on {meta.full_name}")],
                remediation="Check what this fork changed relative to its parent.",
            )
        )

    if age < VERY_YOUNG_DAYS:
        findings.append(
            Finding(
                rule_id="trust.very_new",
                area=Area.REPOSITORY_TRUST,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                title=f"Repository is {age} days old",
                explanation=(
                    "Brand new is not suspicious in itself - everything is new once - but "
                    "there is little history to judge, and no track record of the author "
                    "responding to problems."
                ),
                evidence=[Evidence(detail=f"created {meta.created_at[:10]}")],
            )
        )

    if extras and extras.contributors is not None and extras.contributors < SINGLE_MAINTAINER_THRESHOLD:
        findings.append(
            Finding(
                rule_id="trust.single_maintainer",
                area=Area.MAINTENANCE,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                title="Single contributor",
                explanation=(
                    "One person's account is the whole supply chain: if it is "
                    "compromised, there is no second reviewer between that and a release. "
                    "Extremely common for good small projects - it raises the value of "
                    "reading the source yourself, it does not condemn the project."
                ),
                evidence=[Evidence(detail=f"{extras.contributors} contributor(s) on the first page")],
            )
        )

    if extras and extras.releases == 0 and extras.errors == []:
        findings.append(
            Finding(
                rule_id="trust.no_releases",
                area=Area.REPOSITORY_TRUST,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="No published releases",
                explanation=(
                    "With no tagged release there is no stable point to pin to, so "
                    "installing means taking whatever the default branch holds at that "
                    "moment - which can change between your review and your install."
                ),
                evidence=[Evidence(detail="0 releases returned by the GitHub API")],
                remediation="Pin to a specific commit hash if you install this.",
            )
        )

    owner_note = (
        f"owned by {meta.owner_login} ({meta.owner_type or 'unknown account type'})"
        if meta.owner_login else "owner unknown"
    )
    trust_summary = (
        f"{owner_note}; created {meta.created_at[:10]}; "
        f"licence {meta.license or 'none'}"
        + ("; fork" if meta.is_fork else "")
        + ("; archived" if meta.archived else "")
    )
    maintenance_summary = (
        f"last push {meta.pushed_at[:10]} ({days_since_push} days ago)"
        + (f"; {extras.contributors} contributor(s)" if extras and extras.contributors is not None else "")
        + (f"; {extras.releases} release(s)" if extras and extras.releases is not None else "")
    )

    return (
        AreaAssessment(Area.REPOSITORY_TRUST, trust_severity, Status.VERIFIED, trust_summary),
        AreaAssessment(Area.MAINTENANCE, maintenance_severity, Status.VERIFIED, maintenance_summary),
        findings,
    )
