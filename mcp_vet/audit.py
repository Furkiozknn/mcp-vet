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
from .scanning import ScanResult, scan_tree, source_files

DOC_EXTENSIONS = {".md", ".txt"}


def analyze_tree(result: ScanResult, purpose: str = "") -> dict:
    """Every static analysis, over an already-scanned tree.

    Shared by both entry points so a local checkout and a GitHub repository are
    judged by exactly the same rules.
    """
    sources = source_files(result)
    docs = [f for f in result.files if f.extension in DOC_EXTENSIONS]

    matches = source_mod.scan_matches(sources)
    flows = source_mod.detect_dataflows(matches)

    findings: List[Finding] = []
    findings.extend(source_mod.matches_to_findings(matches))
    findings.extend(source_mod.dataflow_findings(flows))
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
        "dependencies": dependency_report,
        "scan": result,
    }


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
    report.findings = analysis["findings"]
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
        report.capabilities = analysis["capabilities"]
        report.credentials = analysis["credentials"]
        report.endpoints = analysis["endpoints"]
        report.dataflows = analysis["dataflows"]
        _scan_notes(report, result, analysis["dependencies"])
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

    return risk_mod.finalize(report)
