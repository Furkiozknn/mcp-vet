"""Rendering an AuditReport for a terminal, a CI log, or another program.

Two rules shape everything here.

**No colour, no cursor tricks.** Output goes into CI logs and into an agent's
context as often as onto a screen, and every scrap of text in a report is
derived from an untrusted repository. Emitting escape sequences of our own
would make it impossible for a reader to tell ours from theirs. Content is
sanitized upstream in `scanning`; this module then adds nothing that needs
sanitizing.

**Severity always travels with confidence.** A bare "HIGH" invites either
panic or dismissal. "HIGH severity / LOW confidence" invites the correct
response, which is to go and look.
"""
from __future__ import annotations

from typing import List, Optional, Sequence

from .models import (
    Area,
    AuditReport,
    Capability,
    Confidence,
    CredentialRequirement,
    DataFlow,
    Finding,
    NetworkEndpoint,
    Severity,
    Status,
)

RULE = "─" * 62

_AREA_LABELS = {
    Area.POPULARITY_INTEGRITY: "Popularity integrity",
    Area.REPOSITORY_TRUST: "Repository trust",
    Area.SOURCE_CODE: "Source code",
    Area.DEPENDENCIES: "Dependencies",
    Area.INSTALLATION: "Installation",
    Area.CAPABILITIES: "Capabilities",
    Area.NETWORK: "Network",
    Area.PROMPT_INJECTION: "Prompt injection",
    Area.MAINTENANCE: "Maintenance",
    Area.PROVENANCE: "Provenance",
}


def _status_note(status: Status) -> str:
    return {
        Status.VERIFIED: "",
        Status.UNAVAILABLE: "  (not checked - data source unavailable)",
        Status.NOT_APPLICABLE: "  (not applicable)",
        Status.NOT_CHECKED: "  (not checked)",
    }[status]


def render_text(report: AuditReport, verbose: bool = False, quiet: bool = False) -> str:
    lines: List[str] = []

    if quiet:
        lines.append(f"{report.overall.value}  {report.target}")
        lines.append(report.recommendation)
        return "\n".join(lines)

    lines.append("MCP VET")
    lines.append(RULE)
    lines.append("")
    lines.append(f"Target          {report.target}")
    if report.source_url:
        lines.append(f"Source          {report.source_url}")
    if report.version:
        lines.append(f"Version         {report.version}")
    lines.append("")
    lines.append(f"OVERALL RISK    {report.overall.value}")
    lines.append("")

    # Per-area rows. Never summed - the point is that one bad area is not
    # cancelled out by nine good ones.
    if report.areas:
        lines.append("Risk by area")
        for assessment in report.areas:
            label = _AREA_LABELS.get(assessment.area, assessment.area.value)
            lines.append(
                f"  {label:<22}{assessment.severity.value}{_status_note(assessment.status)}"
            )
            if verbose and assessment.summary:
                lines.append(f"      {assessment.summary}")
        lines.append("")

    lines.extend(_capabilities_block(report.capabilities))
    lines.extend(_credentials_block(report.credentials))
    lines.extend(_endpoints_block(report.endpoints))
    lines.extend(_dataflow_block(report.dataflows))
    lines.extend(_findings_block(report.sorted_findings(), verbose))

    lines.append("Recommendation")
    lines.append(f"  {report.recommendation}")
    lines.append("")

    if report.limitations:
        lines.append("What this did not check")
        for limitation in report.limitations:
            lines.append(f"  - {limitation}")
        lines.append("")

    return "\n".join(lines)


def _capabilities_block(capabilities: Sequence[Capability]) -> List[str]:
    if not capabilities:
        return []
    lines = ["Capabilities detected"]
    for capability in capabilities:
        where = ""
        if capability.evidence and capability.evidence[0].path:
            first = capability.evidence[0]
            where = f"  ({first.path}" + (f":{first.line}" if first.line else "") + ")"
        lines.append(f"  {capability.name}{where}")
    lines.append("")
    return lines


def _credentials_block(credentials: Sequence[CredentialRequirement]) -> List[str]:
    if not credentials:
        return []
    lines = ["Credentials expected"]
    for credential in credentials:
        requirement = "required" if credential.required else "optional"
        lines.append(f"  {credential.name}  ({requirement}, read from {credential.source})")
        lines.append(f"      blast radius: {credential.blast_radius}")
    lines.append("")
    return lines


def _endpoints_block(endpoints: Sequence[NetworkEndpoint]) -> List[str]:
    if not endpoints:
        return []
    lines = ["Network destinations"]
    for endpoint in endpoints:
        lines.append(f"  {endpoint.classification.value:<15}{endpoint.host}")
    lines.append("")
    return lines


def _dataflow_block(flows: Sequence[DataFlow]) -> List[str]:
    if not flows:
        return []
    lines = ["Possible data flows (co-location, not proven taint)"]
    for flow in flows:
        destination = f" -> {flow.destination}" if flow.destination else ""
        location = ""
        if flow.evidence and flow.evidence[0].path:
            location = f"   [{flow.evidence[0].path}]"
        lines.append(
            f"  {flow.source} -> {flow.sink}{destination}"
            f"  (confidence {flow.confidence.value}){location}"
        )
    lines.append("")
    return lines


def _findings_block(findings: Sequence[Finding], verbose: bool) -> List[str]:
    if not findings:
        return ["Findings", "  None from the checks that ran.", ""]

    lines = ["Findings"]
    for finding in findings:
        lines.append(
            f"  [{finding.severity.value}/{finding.confidence.value} confidence] {finding.title}"
        )
        for line in _wrap(finding.explanation, width=72, indent=6):
            lines.append(line)
        for evidence in finding.evidence[: (8 if verbose else 3)]:
            location = evidence.path or ""
            if evidence.line:
                location += f":{evidence.line}"
            detail = f" ({evidence.detail})" if evidence.detail and verbose else ""
            if location:
                lines.append(f"      {location}{detail}")
            elif evidence.detail:
                lines.append(f"      {evidence.detail}")
            if evidence.snippet and verbose:
                lines.append(f"        | {evidence.snippet}")
        if finding.remediation:
            for line in _wrap(f"-> {finding.remediation}", width=72, indent=6):
                lines.append(line)
        lines.append("")
    return lines


def _wrap(text: str, width: int, indent: int) -> List[str]:
    """Wrap without importing textwrap's paragraph handling.

    Kept manual so a single pathological token cannot blow the layout - a
    repository controls this text, and a 50,000-character 'word' should not
    become a 50,000-character line.
    """
    pad = " " * indent
    out: List[str] = []
    current = ""
    for word in text.split():
        while len(word) > width:
            if current:
                out.append(pad + current)
                current = ""
            out.append(pad + word[:width])
            word = word[width:]
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            out.append(pad + current)
            current = word
    if current:
        out.append(pad + current)
    return out


def render_search_table(rows: Sequence[tuple]) -> str:
    """Ranked candidate table for `search`.

    Repository names are truncated rather than padded to a fixed width: a
    260-character repository name is a real thing an attacker can create, and
    it should not be able to shear the table apart.
    """
    if not rows:
        return "No candidates found."

    header = f"{'#':<3}{'repository':<42}{'stars':>7}{'forks':>7}{'age(d)':>8}{'ratio':>8}  flag"
    lines = [header, "-" * len(header)]
    for index, (meta, result) in enumerate(rows, start=1):
        flag = "POPULARITY-FLAGGED" if result["suspicious"] else ""
        name = meta.full_name
        if len(name) > 41:
            name = name[:38] + "..."
        lines.append(
            f"{index:<3}{name:<42}{meta.stars:>7}{meta.forks:>7}"
            f"{result['age_days']:>8}{result['fork_ratio']:>8.3f}  {flag}"
        )
    lines.append("")
    lines.append(
        "This table ranks one gameable signal and nothing else. Not flagged is not "
        "vetted: run `mcp-vet audit <owner>/<repo>` on a candidate before installing it."
    )
    return "\n".join(lines)
