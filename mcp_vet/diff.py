"""What changed, security-wise, between two versions.

The most dangerous MCP update is not the one that arrives malicious. It is the
one that was fine at v1.2.0, got read and approved, and quietly grew shell
execution at v1.3.0. Nobody re-reads a patch bump.

This module answers one question: **did this version gain capability it did not
have before?** New network access, new credential reads, new subprocess calls,
a new install hook, a new tool description written at the model. Losing a
capability is reported too, since a server that stops needing your token is
worth knowing about as well.

Two ways to run it, with different fidelity, and the report says which was used:

* **Two local checkouts** - both trees are analyzed in full, so cross-file
  combinations are visible.
* **Two git refs** - only the files the compare API reports as changed are
  fetched and analyzed. That keeps an audit to a handful of requests instead of
  hundreds, at the cost of missing a combination whose halves sit in files that
  did not change. Stated as a limitation rather than glossed over.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import source as source_mod
from urllib.parse import quote

from .github import GITHUB_API, fetch_file
from .http import FetchError, get_json
from .models import (
    Area,
    Confidence,
    Evidence,
    Finding,
    Severity,
)
from .scanning import ScannedFile, SOURCE_EXTENSIONS, sanitize_text, scan_tree, source_files

# A compare with more changed files than this is a rewrite, not an update, and
# fetching each side of each file would turn one audit into hundreds of calls.
MAX_CHANGED_FILES = 60

# Capabilities whose appearance in a new version is worth escalating on its own.
_ESCALATION_SEVERITY = {
    "shell.execute": Severity.HIGH,
    "code.eval": Severity.HIGH,
    "code.remote_execution": Severity.CRITICAL,
    "credentials.ssh": Severity.CRITICAL,
    "credentials.cloud": Severity.CRITICAL,
    "credentials.browser": Severity.CRITICAL,
    "credentials.netrc": Severity.HIGH,
    "credentials.keychain": Severity.HIGH,
    "persistence.startup": Severity.HIGH,
    "persistence.scheduler": Severity.HIGH,
    "process.spawn": Severity.MEDIUM,
    "network.external": Severity.MEDIUM,
    "network.socket": Severity.MEDIUM,
    "environment.read": Severity.MEDIUM,
    "filesystem.write": Severity.LOW,
    "filesystem.delete": Severity.MEDIUM,
    "package.install": Severity.MEDIUM,
}


@dataclass
class DiffResult:
    before_ref: str
    after_ref: str
    mode: str                       # "local" | "refs"
    capabilities_added: List[str] = field(default_factory=list)
    capabilities_removed: List[str] = field(default_factory=list)
    credentials_added: List[str] = field(default_factory=list)
    credentials_removed: List[str] = field(default_factory=list)
    endpoints_added: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    changed_files: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def risk_increased(self) -> bool:
        return bool(self.capabilities_added or self.credentials_added or self.findings)


def _profile(files: Sequence[ScannedFile]) -> Tuple[Set[str], Set[str], Set[str], List]:
    """(capabilities, credential names, hosts, matches) for one side."""
    from . import network as network_mod

    matches = source_mod.scan_matches(files)
    capabilities = {m.rule.capability for m in matches if m.rule.capability}
    credentials = {c.name for c in source_mod.extract_credentials(files)}
    hosts = {e.host for e in network_mod.extract_endpoints(files)}
    return capabilities, credentials, hosts, matches


def _findings_for_change(
    added_capabilities: Sequence[str],
    added_credentials: Sequence[str],
    added_hosts: Sequence[str],
    after_matches: Sequence,
    before_ref: str,
    after_ref: str,
) -> List[Finding]:
    findings: List[Finding] = []

    for capability in sorted(added_capabilities):
        severity = _ESCALATION_SEVERITY.get(capability)
        if severity is None:
            continue
        evidence = [
            Evidence(path=m.file.path, line=m.line, snippet=m.text.strip()[:200])
            for m in after_matches
            if m.rule.capability == capability
        ][:3]
        findings.append(
            Finding(
                rule_id=f"diff.capability_added.{capability}",
                area=Area.SOURCE_CODE,
                severity=severity,
                confidence=Confidence.MEDIUM,
                title=f"New capability since {before_ref}: {capability}",
                explanation=(
                    f"{after_ref} can do something {before_ref} could not: {capability}. "
                    "A capability that appears between versions is the update worth "
                    "reading, because an earlier review of this server did not cover it."
                ),
                evidence=evidence,
                remediation=(
                    "Read the diff for these lines specifically. If the change is not "
                    "explained by the release notes, ask why before upgrading."
                ),
            )
        )

    if added_credentials:
        findings.append(
            Finding(
                rule_id="diff.credentials_added",
                area=Area.CAPABILITIES,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title=f"Asks for credentials it did not want in {before_ref}",
                explanation=(
                    "New secrets expected: " + ", ".join(sorted(added_credentials)) + ". "
                    "A server that grows a credential requirement is asking for access "
                    "it previously did not need."
                ),
                evidence=[Evidence(detail=name) for name in sorted(added_credentials)],
                remediation="Confirm the new credential is required for a feature you actually want.",
            )
        )

    if added_hosts:
        findings.append(
            Finding(
                rule_id="diff.endpoints_added",
                area=Area.NETWORK,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                title=f"Contacts hosts it did not contact in {before_ref}",
                explanation=(
                    "New destinations: " + ", ".join(sorted(added_hosts)[:8]) + "."
                ),
                evidence=[Evidence(detail=host) for host in sorted(added_hosts)[:5]],
                remediation="Check each new destination against what the release claims to add.",
            )
        )

    return findings


def diff_local(before_path: str, after_path: str,
               before_ref: str = "before", after_ref: str = "after") -> DiffResult:
    """Compare two checkouts in full."""
    before_files = source_files(scan_tree(before_path))
    after_files = source_files(scan_tree(after_path))

    before_caps, before_creds, before_hosts, _ = _profile(before_files)
    after_caps, after_creds, after_hosts, after_matches = _profile(after_files)

    result = DiffResult(before_ref=before_ref, after_ref=after_ref, mode="local")
    result.capabilities_added = sorted(after_caps - before_caps)
    result.capabilities_removed = sorted(before_caps - after_caps)
    result.credentials_added = sorted(after_creds - before_creds)
    result.credentials_removed = sorted(before_creds - after_creds)
    result.endpoints_added = sorted(after_hosts - before_hosts)
    result.findings = _findings_for_change(
        result.capabilities_added, result.credentials_added, result.endpoints_added,
        after_matches, before_ref, after_ref,
    )
    return result


def diff_refs(owner_repo: str, before_ref: str, after_ref: str) -> DiffResult:
    """Compare two git refs, fetching only the files that actually changed."""
    result = DiffResult(before_ref=before_ref, after_ref=after_ref, mode="refs")

    # Refs are user-supplied and may contain slashes (release/1.2) or other
    # characters that would otherwise change which endpoint is addressed.
    base = quote(before_ref, safe="")
    head = quote(after_ref, safe="")
    compare = get_json(f"{GITHUB_API}/repos/{owner_repo}/compare/{base}...{head}")
    entries = compare.get("files") or [] if isinstance(compare, dict) else []
    paths = [
        sanitize_text(entry.get("filename", ""))
        for entry in entries
        if isinstance(entry, dict) and entry.get("filename")
    ]
    interesting = [p for p in paths if any(p.endswith(ext) for ext in SOURCE_EXTENSIONS)]
    result.changed_files = interesting

    if len(interesting) > MAX_CHANGED_FILES:
        result.truncated = True
        result.limitations.append(
            f"{len(interesting)} source files changed; only the first "
            f"{MAX_CHANGED_FILES} were fetched. A change this large is better "
            "reviewed as a fresh audit than as a diff."
        )
        interesting = interesting[:MAX_CHANGED_FILES]

    result.limitations.append(
        "Only files reported as changed were analyzed. A finding whose halves sit "
        "in files that did not change will not appear here - run a full audit of "
        f"{after_ref} for that."
    )

    before_files = _fetch_side(owner_repo, interesting, before_ref)
    after_files = _fetch_side(owner_repo, interesting, after_ref)

    before_caps, before_creds, before_hosts, _ = _profile(before_files)
    after_caps, after_creds, after_hosts, after_matches = _profile(after_files)

    result.capabilities_added = sorted(after_caps - before_caps)
    result.capabilities_removed = sorted(before_caps - after_caps)
    result.credentials_added = sorted(after_creds - before_creds)
    result.credentials_removed = sorted(before_creds - after_creds)
    result.endpoints_added = sorted(after_hosts - before_hosts)
    result.findings = _findings_for_change(
        result.capabilities_added, result.credentials_added, result.endpoints_added,
        after_matches, before_ref, after_ref,
    )
    return result


def _fetch_side(owner_repo: str, paths: Sequence[str], ref: str) -> List[ScannedFile]:
    """Read the given paths at one ref. A file absent at that ref is simply skipped."""
    files: List[ScannedFile] = []
    for path in paths:
        try:
            text = fetch_file(owner_repo, path, ref=ref)
        except FetchError:
            continue
        if text is None:
            continue
        files.append(
            ScannedFile(path=path, text=text, lines=text.splitlines(), size_bytes=len(text))
        )
    return files


def render(result: DiffResult) -> str:
    lines = [
        "MCP VET - version diff",
        "─" * 62,
        "",
        f"Comparing       {result.before_ref} -> {result.after_ref}",
        f"Analysis        {'both trees in full' if result.mode == 'local' else 'changed files only'}",
    ]
    if result.changed_files:
        lines.append(f"Changed files   {len(result.changed_files)}")
    lines.append("")

    if not result.risk_increased and not result.capabilities_removed:
        lines.append("No security-relevant change detected by these checks.")
        lines.append("That is not the same as 'no meaningful change' - logic can change")
        lines.append("substantially without any new capability appearing.")
        lines.append("")
    else:
        if result.capabilities_added:
            lines.append("Capabilities gained")
            for name in result.capabilities_added:
                lines.append(f"  + {name}")
            lines.append("")
        if result.capabilities_removed:
            lines.append("Capabilities dropped")
            for name in result.capabilities_removed:
                lines.append(f"  - {name}")
            lines.append("")
        if result.credentials_added:
            lines.append("Credentials newly requested")
            for name in result.credentials_added:
                lines.append(f"  + {name}")
            lines.append("")
        if result.endpoints_added:
            lines.append("Network destinations added")
            for host in result.endpoints_added:
                lines.append(f"  + {host}")
            lines.append("")

    if result.findings:
        from .report import _findings_block

        lines.extend(_findings_block(sorted(result.findings, key=lambda f: -f.severity.rank), False))

    if result.limitations:
        lines.append("What this diff did not check")
        for limitation in result.limitations:
            lines.append(f"  - {limitation}")
        lines.append("")

    return "\n".join(lines)
