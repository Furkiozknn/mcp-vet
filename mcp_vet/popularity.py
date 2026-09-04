"""The original star/fork/age heuristic, kept intact and renamed in concept.

This was mcp-vet's first and only check. It is still useful and it is still
here, unchanged in behaviour and thresholds - but it is deliberately *not* a
security signal, and calling it one was the single most misleading thing about
the old tool. A repo can pass this and be malware; it can fail it and be a
perfectly good project that had a good launch week.

What it actually measures is whether a repository's popularity numbers relate
to each other the way real adoption usually makes them relate. Hence
"Popularity Integrity": an integrity check on one signal, not a verdict on the
software.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .models import (
    Area,
    AreaAssessment,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Status,
)

# Unchanged from the original implementation, and still cited by exact value in
# every report so a reader can disagree with the threshold rather than the
# verdict.
SUSPICIOUS_STAR_THRESHOLD = 3000
SUSPICIOUS_AGE_DAYS = 180
SUSPICIOUS_FORK_RATIO = 0.12

STALE_DAYS = 180


def parse_iso(timestamp: str) -> datetime:
    """Parse a GitHub UTC timestamp like '2024-01-01T00:00:00Z'.

    GitHub also emits offset forms such as '+00:00' on some endpoints, so both
    are accepted rather than crashing the whole audit on a timestamp variant.
    """
    text = timestamp.strip()
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"unrecognised timestamp: {timestamp!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def age_days(created_at: str, now: datetime) -> int:
    return (now - parse_iso(created_at)).days


def fork_ratio(forks: int, stars: int) -> float:
    return forks / stars if stars > 0 else 0.0


def is_suspicious(stars: int, forks: int, created_at: str, now: datetime) -> bool:
    """Flagged only when all three conditions hold at once."""
    if not (stars > SUSPICIOUS_STAR_THRESHOLD):
        return False
    if not (age_days(created_at, now) < SUSPICIOUS_AGE_DAYS):
        return False
    return fork_ratio(forks, stars) < SUSPICIOUS_FORK_RATIO


def assess(meta, now: Optional[datetime] = None):
    """Return (AreaAssessment, findings) for the popularity integrity signal."""
    now = now or datetime.now(timezone.utc)
    flagged = is_suspicious(meta.stars, meta.forks, meta.created_at, now)
    ratio = fork_ratio(meta.forks, meta.stars)
    days = age_days(meta.created_at, now)
    findings = []

    if flagged:
        findings.append(
            Finding(
                rule_id="popularity.inflated_star_pattern",
                area=Area.POPULARITY_INTEGRITY,
                severity=Severity.MEDIUM,
                # The arithmetic is certain; what it implies is not. A young
                # official-org repo trips this legitimately, so the confidence
                # is about the interpretation, not the measurement.
                confidence=Confidence.LOW,
                title="Popularity numbers do not fit the usual adoption pattern",
                explanation=(
                    f"{meta.stars} stars on a {days}-day-old repository with only "
                    f"{meta.forks} forks (ratio {ratio:.3f}). Genuine adoption normally "
                    f"accumulates forks roughly in proportion to age and attention. All "
                    f"three flag conditions hold at once: stars > {SUSPICIOUS_STAR_THRESHOLD}, "
                    f"age < {SUSPICIOUS_AGE_DAYS} days, forks/stars < {SUSPICIOUS_FORK_RATIO}. "
                    "This is a disclosed flag about one gameable number, not a finding "
                    "about the code."
                ),
                evidence=[
                    Evidence(
                        detail=(
                            f"stars={meta.stars} forks={meta.forks} "
                            f"ratio={ratio:.3f} age_days={days}"
                        )
                    )
                ],
                remediation=(
                    "Weigh the source review more heavily than the star count here. "
                    "Check whether the stars arrived gradually or in a single burst, "
                    "and whether the issue tracker shows real users."
                ),
            )
        )
        summary = (
            f"Star/fork/age pattern flagged ({meta.stars} stars, {meta.forks} forks, "
            f"{days} days old)."
        )
        severity = Severity.MEDIUM
    else:
        summary = (
            f"Not flagged: {meta.stars} stars, {meta.forks} forks (ratio {ratio:.3f}), "
            f"{days} days old. Not flagged is not the same as vetted."
        )
        severity = Severity.NOT_FLAGGED

    return (
        AreaAssessment(
            area=Area.POPULARITY_INTEGRITY,
            severity=severity,
            status=Status.VERIFIED,
            summary=summary,
        ),
        findings,
    )
