"""Orchestration: run the analyzers over one target and assemble the report.

Two entry points, because there are two honest ways to look at a server:

* `audit_directory` - a local checkout. Everything static is available, and
  nothing about GitHub is. This is what `--offline` uses.
* `audit_repository` - a GitHub repository. Adds trust, popularity, provenance
  and (optionally) reads source through the API without cloning.

The rule running through both: an analysis that could not run is recorded as
UNAVAILABLE or NOT_CHECKED, never omitted. A report with a missing section
reads as a clean section, and that is the failure mode this whole tool exists
to avoid.
"""
from __future__ import annotations

import os
from typing import List, Optional, Sequence

from . import dependencies as deps_mod
from . import injection as injection_mod
from . import install as install_mod
from . import network as network_mod
from . import popularity as popularity_mod
from . import registry as registry_mod
from . import risk as risk_mod
from . import source as source_mod
from . import trust as trust_mod
from . import http as http_mod
from .github import RepoExtras, RepoMeta, fetch_extras, fetch_repo
from .http import FetchError
from .models import (
    Area,
    AreaAssessment,
    AuditReport,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Status,
)
from .scanning import (
    DOCS,
    MAX_FILE_BYTES,
    MAX_FILES_SCANNED,
    SOURCE_EXTENSIONS,
    ScanResult,
    file_role,
    sanitize_text,
    scan_tree,
    source_files,
)

DOC_EXTENSIONS = {".md", ".txt"}


def _documentation_text(result: ScanResult) -> str:
    """What the repository tells a reader about itself: its docs and server.json.

    Used for one question only - whether a provider a server sends a credential
    to is one it names (provider.py). Bounded so a huge docs tree cannot make
    that question expensive.
    """
    parts = [
        f.text for f in result.files
        if file_role(f.path) == DOCS or os.path.basename(f.path).lower() == "server.json"
    ]
    return "\n".join(parts)[:2_000_000]


def analyze_tree(result: ScanResult, purpose: str = "") -> dict:
    """Every static analysis, over an already-scanned tree.

    Shared by both entry points so a local checkout and a GitHub repository are
    judged by exactly the same rules.
    """
    sources = source_files(result)
    docs = [f for f in result.files if f.extension in DOC_EXTENSIONS]

    matches = source_mod.scan_matches(sources)
    # Findings are drawn from every flow; only the table is capped. Capping
    # first let a dozen unrelated pairs push a LOW-confidence
    # environment -> network pair out of the list and, with it, its HIGH
    # finding - which is how mcp-vet stopped reporting its own GITHUB_TOKEN
    # flow in http.py, the one SECURITY.md walks through.
    all_flows = source_mod.detect_dataflows(matches, _documentation_text(result), limit=None)
    flows = all_flows[:source_mod.MAX_FLOWS_REPORTED]

    findings: List[Finding] = []
    findings.extend(source_mod.matches_to_findings(matches))
    findings.extend(source_mod.dataflow_findings(all_flows))
    findings.extend(source_mod.combination_findings(matches))
    findings.extend(injection_mod.analyze(sources, docs))
    findings.extend(install_mod.analyze(result))

    dependency_report = deps_mod.analyze(result)
    findings.extend(deps_mod.findings_for(dependency_report, None))

    endpoints = network_mod.extract_endpoints(result.files, purpose)
    findings.extend(network_mod.findings_for(endpoints))

    return {
        "findings": findings,
        "capabilities": source_mod.matches_to_capabilities(matches),
        "credentials": source_mod.extract_credentials(sources),
        "endpoints": endpoints,
        "dataflows": flows,
        "dataflows_total": len(all_flows),
        "dependencies": dependency_report,
        "scan": result,
    }


def _flow_note(report: AuditReport, analysis: dict) -> None:
    """Say so when the data-flow table was cut short."""
    hidden = analysis["dataflows_total"] - len(analysis["dataflows"])
    if hidden > 0:
        report.limitations.append(
            f"{hidden} further data flow(s) were not listed; every one of them was "
            "still considered for the findings above."
        )


def _is_source(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in SOURCE_EXTENSIONS


def unanalyzed_findings(result: ScanResult) -> List[Finding]:
    """Source files the scan skipped, as findings that can move the verdict.

    A limitation line alone left the headline and the exit code untouched, so
    a server that put its payload in a 600 KB `server.py`, in a `.js` file
    with a NUL byte near the top, or past the file-count limit, came out NOT
    FLAGGED with exit 0 - the one thing a CI gate reads as "passed". Not
    having read the code is not evidence that it is clean.

    Only files with a source extension count: an oversized `package-lock.json`
    or README is not code that runs. Each skipped file is its own piece of
    evidence, so the usual headline rule applies per file - a huge test
    fixture is reported but does not decide the verdict, an oversized file in
    the shipped server does.
    """
    findings: List[Finding] = []
    limit_kb = MAX_FILE_BYTES // 1024

    too_large = [(p, n) for p, n in result.skipped_too_large if _is_source(p)]
    if too_large:
        findings.append(Finding(
            area=Area.SOURCE_CODE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title=f"{len(too_large)} source file(s) too large to analyze",
            explanation=(
                f"These files are over the {limit_kb} KB per-file limit, so none of "
                "the checks read them. Whatever they do is not in this report, and "
                "a large file is a known place to hide code from a scanner."
            ),
            evidence=[Evidence(path=sanitize_text(p), detail=f"{n} bytes, not read") for p, n in too_large],
            remediation="Read these files yourself before relying on this verdict.",
            rule_id="source.unanalyzed_too_large",
        ))

    unread = sorted(
        [p for p in result.skipped_unreadable if _is_source(p)]
        + [p for p in result.skipped_binary if _is_source(p)]
    )
    if unread:
        findings.append(Finding(
            area=Area.SOURCE_CODE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title=f"{len(unread)} source file(s) could not be analyzed",
            explanation=(
                "These files have a source extension but were not read: the "
                "operating system refused them, or they contain a NUL byte and "
                "were taken for binary. None of the checks covered them."
            ),
            evidence=[Evidence(path=sanitize_text(p), detail="not read") for p in unread],
            remediation="Read these files yourself before relying on this verdict.",
            rule_id="source.unanalyzed_unreadable",
        ))

    if result.hit_file_limit:
        findings.append(Finding(
            area=Area.SOURCE_CODE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="File-count limit reached; part of the tree was not analyzed",
            explanation=(
                f"The scan stops after {MAX_FILES_SCANNED} files, and this tree has "
                "more. Files past the limit were not read, so the verdict does not "
                "cover them."
            ),
            remediation="Audit the server's own directory with --path, not a parent of it.",
            rule_id="source.file_limit_reached",
        ))
    return findings


def _scan_notes(report: AuditReport, result: ScanResult, dependency_report) -> None:
    """Record what was and was not read, so limits are visible rather than implied."""
    report.notes["files_scanned"] = len(result.files)
    if result.skipped_too_large:
        report.notes["skipped_too_large"] = [
            {"path": p, "bytes": n} for p, n in result.skipped_too_large[:20]
        ]
        report.limitations.append(
            f"{len(result.skipped_too_large)} file(s) exceeded the size limit and were "
            "not analyzed. Code can be hidden in a large file deliberately."
        )
    if result.skipped_binary:
        report.notes["skipped_binary"] = result.skipped_binary[:20]
        report.limitations.append(
            f"{len(result.skipped_binary)} binary file(s) were not analyzed. "
            "mcp-vet does not inspect compiled artifacts."
        )
    if result.skipped_unreadable:
        report.notes["skipped_unreadable"] = result.skipped_unreadable[:20]
        report.limitations.append(
            f"{len(result.skipped_unreadable)} file(s) could not be read (permission denied "
            "or an I/O error) and were not analyzed. A clean result does not cover them."
        )
    if result.hit_file_limit:
        report.limitations.append(
            "The file-count limit was reached; part of the tree was not scanned."
        )

    report.notes["dependencies"] = {
        "ecosystem": dependency_report.ecosystem,
        "manifest": dependency_report.manifest_path,
        "lockfile": dependency_report.lockfile_path,
        "direct": dependency_report.direct_count,
        "locked": dependency_report.locked_count,
        "vulnerability_status": "unavailable",
    }
    # The standing limitation set already states this; repeating it here only
    # when a manifest actually exists keeps it from reading as boilerplate.
    if dependency_report.manifest_path:
        report.limitations.append(
            f"Dependencies in {dependency_report.manifest_path} were enumerated but not "
            "checked against any advisory database. Vulnerability status unavailable."
        )
    for note in dependency_report.notes:
        report.limitations.append(note)


def audit_directory(path: str, purpose: str = "", target: Optional[str] = None) -> AuditReport:
    """Audit a local checkout. No network access at all."""
    result = scan_tree(path)
    analysis = analyze_tree(result, purpose)

    report = AuditReport(target=target or os.path.basename(os.path.abspath(path)))
    report.findings = analysis["findings"] + unanalyzed_findings(result)
    report.capabilities = analysis["capabilities"]
    report.credentials = analysis["credentials"]
    report.endpoints = analysis["endpoints"]
    report.dataflows = analysis["dataflows"]

    # Areas that genuinely could not be assessed offline. Recorded explicitly
    # so the reader sees a gap rather than an absence.
    for area, note in (
        (Area.POPULARITY_INTEGRITY, "Not checked: offline mode makes no GitHub requests."),
        (Area.REPOSITORY_TRUST, "Not checked: offline mode makes no GitHub requests."),
        (Area.MAINTENANCE, "Not checked: offline mode makes no GitHub requests."),
        (Area.PROVENANCE, "Not checked: offline mode does not query the MCP Registry."),
    ):
        report.areas.append(
            AreaAssessment(area, Severity.NOT_FLAGGED, Status.NOT_CHECKED, note)
        )

    _scan_notes(report, result, analysis["dependencies"])
    _flow_note(report, analysis)
    return risk_mod.finalize(report)


def audit_repository(
    owner_repo: str,
    local_path: Optional[str] = None,
    check_registry: bool = True,
    fetch_repo_extras: bool = True,
) -> AuditReport:
    """Audit a GitHub repository, optionally alongside a local checkout.

    Metadata always comes from the API. Source analysis runs only when a local
    checkout is supplied - mcp-vet does not clone, by design, so that decision
    stays with the person running it.
    """
    network_before = http_mod.cache_stats()
    meta: RepoMeta = fetch_repo(owner_repo)
    report = AuditReport(target=meta.full_name, source_url=meta.html_url)
    purpose = f"{meta.full_name} {meta.description or ''} {' '.join(meta.topics)}"

    popularity_assessment, popularity_findings = popularity_mod.assess(meta)
    report.areas.append(popularity_assessment)
    report.findings.extend(popularity_findings)

    extras: Optional[RepoExtras] = None
    if fetch_repo_extras:
        try:
            extras = fetch_extras(owner_repo)
        except FetchError:
            extras = None
    trust_assessment, maintenance_assessment, trust_findings = trust_mod.assess(meta, extras)
    report.areas.extend([trust_assessment, maintenance_assessment])
    report.findings.extend(trust_findings)

    report.notes["popularity"] = {
        "stars": meta.stars,
        "forks": meta.forks,
        "fork_ratio": round(popularity_mod.fork_ratio(meta.forks, meta.stars), 4),
        "archived": meta.archived,
        "license": meta.license,
        "owner_type": meta.owner_type,
    }
    if extras:
        report.notes["repository"] = {
            "contributors_first_page": extras.contributors,
            "releases": extras.releases,
            "latest_release": extras.latest_release_tag,
            "errors": extras.errors,
        }

    if check_registry:
        try:
            server = registry_mod.find_by_repository(meta.html_url)
            provenance, provenance_findings = registry_mod.assess_provenance(
                server, meta.full_name, lookup_failed=False
            )
            if server:
                report.version = server.version
                report.notes["registry"] = {
                    "name": server.name,
                    "version": server.version,
                    "transports": server.transports,
                    "remote_only": server.is_remote_only,
                    "status": server.status,
                }
        except FetchError:
            provenance, provenance_findings = registry_mod.assess_provenance(
                None, meta.full_name, lookup_failed=True
            )
        report.areas.append(provenance)
        report.findings.extend(provenance_findings)
    else:
        report.areas.append(
            AreaAssessment(
                Area.PROVENANCE, Severity.NOT_FLAGGED, Status.NOT_CHECKED,
                "Registry lookup skipped by request.",
            )
        )

    if local_path:
        result = scan_tree(local_path)
        analysis = analyze_tree(result, purpose)
        report.findings.extend(analysis["findings"])
        report.findings.extend(unanalyzed_findings(result))
        report.capabilities = analysis["capabilities"]
        report.credentials = analysis["credentials"]
        report.endpoints = analysis["endpoints"]
        report.dataflows = analysis["dataflows"]
        _scan_notes(report, result, analysis["dependencies"])
        _flow_note(report, analysis)
    else:
        for area in (Area.SOURCE_CODE, Area.CAPABILITIES, Area.NETWORK,
                     Area.PROMPT_INJECTION, Area.DEPENDENCIES, Area.INSTALLATION):
            report.areas.append(
                AreaAssessment(
                    area, Severity.NOT_FLAGGED, Status.NOT_CHECKED,
                    "No local checkout supplied, so no source was analyzed. "
                    "Metadata alone cannot tell you what the code does.",
                )
            )
        report.limitations.append(
            "Source code was NOT analyzed. Only repository metadata and registry "
            "provenance were checked. Pass --path <checkout> to analyze the source, "
            "which is the part that decides whether this is safe to run."
        )

    _network_notes(report, http_mod.cache_stats().since(network_before))
    return risk_mod.finalize(report)


def _network_notes(report: AuditReport, stats: http_mod.CacheStats) -> None:
    """Say where the metadata came from. A cached answer is not a live one.

    Revalidated bodies were confirmed current by the server, so only plain
    cache hits - served without asking - are listed as a limitation.
    """
    report.notes["network"] = {
        "requests": stats.requests,
        "cache_hits": stats.hits,
        "revalidated": stats.revalidated,
        "cache_oldest_seconds": int(stats.oldest_seconds),
    }
    if stats.hits:
        report.limitations.append(
            f"{stats.hits} of {stats.hits + stats.requests} API responses came from the "
            f"local cache (the oldest is {http_mod.age_text(stats.oldest_seconds)}), so "
            "repository metadata and registry provenance may lag by that much. "
            "Run with --no-cache for live answers."
        )
