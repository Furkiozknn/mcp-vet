"""Supply chain: what else runs when this server runs.

Reviewing a server's own source and stopping there misses most of the code you
would actually be executing. This module reads manifests and lockfiles to
answer a narrower, more answerable set of questions than "is this dependency
safe":

* How many dependencies are there, and how many are pinned?
* Does any of them come from a git URL or a bare URL rather than a registry?
* Does the package itself declare install-time scripts?

What it deliberately does **not** do is guess at vulnerabilities. Without a
reachable advisory database there is no honest way to say a version is
vulnerable, and inventing one would be worse than silence - so the report says
"vulnerability status unavailable" and means it.

Lockfiles are preferred where present: a manifest says what was asked for, a
lockfile says what would actually be installed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .models import Area, Confidence, Evidence, Finding, Severity, Status
from .scanning import ScannedFile, ScanResult, find_files, snippet

MANIFESTS = [
    "package.json", "requirements.txt", "pyproject.toml", "go.mod",
    "cargo.toml", "gemfile", "composer.json",
]
LOCKFILES = [
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock",
    "poetry.lock", "cargo.lock", "go.sum", "requirements.lock",
]

# npm lifecycle hooks that execute during `npm install` with no further prompt.
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


@dataclass
class DependencyReport:
    status: Status = Status.NOT_APPLICABLE
    ecosystem: Optional[str] = None
    manifest_path: Optional[str] = None
    lockfile_path: Optional[str] = None
    direct_count: int = 0
    locked_count: Optional[int] = None
    unpinned: List[str] = field(default_factory=list)
    remote_sources: List[Tuple[str, str]] = field(default_factory=list)
    install_scripts: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


def _safe_json(scanned: ScannedFile) -> Optional[dict]:
    """Parse JSON, tolerating a malformed file rather than aborting the audit.

    A repository can ship a broken manifest, deliberately or not, and that must
    degrade one section of the report rather than kill the run.
    """
    try:
        data = json.loads(scanned.text)
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


def analyze(result: ScanResult) -> DependencyReport:
    found = find_files(result, MANIFESTS + LOCKFILES)
    if "package.json" in found:
        return _analyze_npm(found)
    if "pyproject.toml" in found or "requirements.txt" in found:
        return _analyze_python(found)
    if "go.mod" in found:
        return _analyze_go(found)
    if "cargo.toml" in found:
        return _analyze_generic(found, "cargo.toml", "rust", "cargo.lock")
    report = DependencyReport(status=Status.NOT_APPLICABLE)
    report.notes.append("No dependency manifest found in the scanned tree.")
    return report


def _analyze_npm(found: Dict[str, ScannedFile]) -> DependencyReport:
    manifest = found["package.json"]
    report = DependencyReport(status=Status.VERIFIED, ecosystem="npm",
                              manifest_path=manifest.path)
    data = _safe_json(manifest)
    if data is None:
        report.status = Status.UNAVAILABLE
        report.notes.append(f"{manifest.path} is not valid JSON; dependencies not read.")
        return report

    deps: Dict[str, str] = {}
    for key in ("dependencies", "optionalDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.update({str(k): str(v) for k, v in section.items()})
    report.direct_count = len(deps)

    for name, spec in sorted(deps.items()):
        if re.match(r"^(?:git\+|github:|git:|https?:|file:)", spec):
            report.remote_sources.append((name, spec))
        elif spec in ("*", "latest", "") or spec.startswith(("^", "~", ">")):
            report.unpinned.append(f"{name}@{spec}")

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in INSTALL_HOOKS:
            value = scripts.get(hook)
            if isinstance(value, str) and value.strip():
                report.install_scripts[hook] = value.strip()

    for lock_name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
        if lock_name in found:
            lock = found[lock_name]
            report.lockfile_path = lock.path
            if lock_name == "package-lock.json":
                lock_data = _safe_json(lock)
                packages = (lock_data or {}).get("packages")
                if isinstance(packages, dict):
                    # The "" key is the root project itself, not a dependency.
                    report.locked_count = len([k for k in packages if k])
            break
    if not report.lockfile_path:
        report.notes.append(
            "No lockfile present, so the exact transitive tree that would be installed "
            "cannot be determined from this repository."
        )
    return report


def _analyze_python(found: Dict[str, ScannedFile]) -> DependencyReport:
    report = DependencyReport(status=Status.VERIFIED, ecosystem="python")
    specs: List[str] = []

    if "requirements.txt" in found:
        scanned = found["requirements.txt"]
        report.manifest_path = scanned.path
        for line in scanned.lines:
            entry = line.split("#", 1)[0].strip()
            if not entry or entry.startswith("-"):
                continue
            specs.append(entry)

    if "pyproject.toml" in found:
        scanned = found["pyproject.toml"]
        report.manifest_path = report.manifest_path or scanned.path
        # A regex rather than a TOML parser: tomllib only exists on 3.11+ and
        # this project supports 3.9. The dependency list is a flat array of
        # strings in practice, which is well within what a regex can read.
        block = re.search(r"^\s*dependencies\s*=\s*\[(.*?)\]", scanned.text,
                          re.DOTALL | re.MULTILINE)
        if block:
            specs.extend(re.findall(r"['\"]([^'\"]+)['\"]", block.group(1)))

    report.direct_count = len(specs)
    for spec in specs:
        if re.search(r"@\s*(?:git\+|https?:)", spec) or spec.startswith(("git+", "http")):
            report.remote_sources.append((spec.split("@")[0].strip(), spec))
        elif not re.search(r"[=<>~!]", spec):
            report.unpinned.append(spec)

    for lock_name in ("uv.lock", "poetry.lock"):
        if lock_name in found:
            report.lockfile_path = found[lock_name].path
            break
    if not report.lockfile_path:
        report.notes.append(
            "No uv.lock or poetry.lock, so transitive dependencies cannot be enumerated."
        )
    return report


def _analyze_go(found: Dict[str, ScannedFile]) -> DependencyReport:
    scanned = found["go.mod"]
    report = DependencyReport(status=Status.VERIFIED, ecosystem="go",
                              manifest_path=scanned.path)
    requires = re.findall(r"^\s*([\w./-]+)\s+v\S+", scanned.text, re.MULTILINE)
    report.direct_count = len(requires)
    if "go.sum" in found:
        report.lockfile_path = found["go.sum"].path
        report.locked_count = len({l.split()[0] for l in found["go.sum"].lines if l.strip()})
    if re.search(r"^\s*replace\s", scanned.text, re.MULTILINE):
        report.notes.append(
            "go.mod contains a `replace` directive, which redirects a module to a "
            "different source than its name implies."
        )
    return report


def _analyze_generic(found, manifest_name, ecosystem, lock_name) -> DependencyReport:
    scanned = found[manifest_name]
    report = DependencyReport(status=Status.VERIFIED, ecosystem=ecosystem,
                              manifest_path=scanned.path)
    block = re.search(r"^\[dependencies\](.*?)(?:^\[|\Z)", scanned.text,
                      re.DOTALL | re.MULTILINE)
    if block:
        report.direct_count = len(re.findall(r"^\s*([\w-]+)\s*=", block.group(1), re.MULTILINE))
    if lock_name in found:
        report.lockfile_path = found[lock_name].path
    return report


def findings_for(report: DependencyReport, manifest: Optional[ScannedFile]) -> List[Finding]:
    findings: List[Finding] = []
    evidence = (
        [Evidence(path=report.manifest_path)] if report.manifest_path else []
    )

    if report.install_scripts:
        hooks = ", ".join(sorted(report.install_scripts))
        detail = "; ".join(f"{k}: {snippet(v, 120)}" for k, v in sorted(report.install_scripts.items()))
        findings.append(
            Finding(
                rule_id="dependencies.install_scripts",
                area=Area.INSTALLATION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=f"package.json declares install-time scripts ({hooks})",
                explanation=(
                    "npm runs these automatically during `npm install`, before you have "
                    "run the server or read anything. Whatever they do happens at install "
                    "time with your user's permissions, and `npm install` is not a "
                    "reviewable step. Commands: " + detail
                ),
                evidence=[Evidence(path=report.manifest_path, detail=detail)],
                remediation=(
                    "Read each script before installing. `npm install --ignore-scripts` "
                    "skips them, though the package may then not work."
                ),
            )
        )

    if report.remote_sources:
        listed = ", ".join(f"{n} ({s})" for n, s in report.remote_sources[:5])
        findings.append(
            Finding(
                rule_id="dependencies.non_registry_source",
                area=Area.DEPENDENCIES,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Depends on code fetched from a git or URL source",
                explanation=(
                    "These bypass the registry, so they miss whatever review, signing and "
                    "immutability the registry provides. A git ref that is a branch rather "
                    "than a tag or commit can change content without the version changing: "
                    + listed
                ),
                evidence=evidence,
                remediation="Pin to an immutable commit hash, or prefer a published release.",
            )
        )

    if report.unpinned and report.direct_count:
        ratio = len(report.unpinned) / report.direct_count
        if ratio > 0.5:
            findings.append(
                Finding(
                    rule_id="dependencies.unpinned",
                    area=Area.DEPENDENCIES,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    title=f"{len(report.unpinned)} of {report.direct_count} dependencies use floating version ranges",
                    explanation=(
                        "With no lockfile, a range means the code installed today may not "
                        "be the code installed tomorrow, and what you reviewed is not "
                        "necessarily what you run."
                    ),
                    evidence=evidence,
                    remediation="Commit a lockfile so installs are reproducible.",
                )
            )

    return findings
