"""What happens between `install` and the server ever being run.

Installation is the step people skip when reviewing, and it is the step that
runs first. npm lifecycle hooks, a setup.py that executes on build, a
Dockerfile that pipes a remote script into a shell - all of these run before
anyone has read a line of the server itself.

mcp-vet never executes any of it. It reads the files that describe
installation and reports what they would do.
"""
from __future__ import annotations

import re
from typing import List, Sequence

from .models import Area, Confidence, Evidence, Finding, Severity
from .scanning import ScanResult, ScannedFile, snippet

_REMOTE_PIPE = re.compile(r"(?:curl|wget)[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|d)?sh")
_REMOTE_FETCH = re.compile(r"(?:curl|wget|Invoke-WebRequest)\s+[^\n]{0,200}https?://")
_BINARY_DOWNLOAD = re.compile(
    r"https?://[^\s'\"]{0,200}\.(?:sh|exe|bin|dmg|pkg|msi|deb|rpm|AppImage)\b"
)
_SETUP_EXECUTES = re.compile(
    r"^\s*(?:import\s+subprocess|from\s+subprocess|os\.system|subprocess\.)", re.MULTILINE
)
_CUSTOM_CMDCLASS = re.compile(r"cmdclass\s*=|class\s+\w*(?:Install|Develop|Build)\w*\s*\(")

_INSTALL_DOC_NAMES = {"readme.md", "install.md", "installation.md", "setup.md",
                      "contributing.md", "docs/install.md"}
_INSTALL_SCRIPT_NAMES = {"install.sh", "setup.sh", "bootstrap.sh", "get.sh"}


def analyze(result: ScanResult) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_remote_execution(result))
    findings.extend(_setup_py(result))
    findings.extend(_dockerfile(result))
    return findings


def _remote_execution(result: ScanResult) -> List[Finding]:
    """curl | sh, wherever it appears - script, Dockerfile or README."""
    hits: List[Evidence] = []
    for scanned in result.files:
        base = scanned.path.lower()
        interesting = (
            base.endswith((".sh", ".bash", ".zsh", ".md"))
            or base.endswith("dockerfile")
            or "dockerfile" in base
        )
        if not interesting:
            continue
        for index, line in enumerate(scanned.lines, start=1):
            if len(line) > 2000:
                continue
            if _REMOTE_PIPE.search(line):
                hits.append(Evidence(path=scanned.path, line=index, snippet=snippet(line)))

    if not hits:
        return []
    return [
        Finding(
            rule_id="install.remote_script_execution",
            area=Area.INSTALLATION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            title="Installation pipes a downloaded script straight into a shell",
            explanation=(
                "Whatever that URL serves at the moment you run it executes with your "
                "permissions. There is no checksum, no signature and nothing for you to "
                "read first, and the content can differ per request or per IP - so the "
                "script a reviewer sees need not be the script you get."
            ),
            evidence=hits[:5],
            remediation=(
                "Download to a file, verify a published checksum, read it, then run it. "
                "If the project offers a registry package instead, prefer that."
            ),
        )
    ]


def _setup_py(result: ScanResult) -> List[Finding]:
    findings: List[Finding] = []
    for scanned in result.files:
        if scanned.path.lower().rsplit("/", 1)[-1] != "setup.py":
            continue
        if _SETUP_EXECUTES.search(scanned.text) or _CUSTOM_CMDCLASS.search(scanned.text):
            findings.append(
                Finding(
                    rule_id="install.setup_py_executes",
                    area=Area.INSTALLATION,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="setup.py runs commands or overrides install steps",
                    explanation=(
                        "setup.py executes during `pip install`, so anything here runs "
                        "before the package is ever imported. A custom cmdclass or a "
                        "subprocess call in a build script is the Python equivalent of an "
                        "npm postinstall hook."
                    ),
                    evidence=[Evidence(path=scanned.path, snippet=snippet(scanned.text[:400]))],
                    remediation=(
                        "Read setup.py in full. `pip install --no-build-isolation` does not "
                        "help here; there is no flag that skips it."
                    ),
                )
            )
    return findings


def _dockerfile(result: ScanResult) -> List[Finding]:
    findings: List[Finding] = []
    for scanned in result.files:
        name = scanned.path.rsplit("/", 1)[-1].lower()
        if "dockerfile" not in name:
            continue
        downloads = [
            Evidence(path=scanned.path, line=i, snippet=snippet(line))
            for i, line in enumerate(scanned.lines, start=1)
            if len(line) <= 2000 and _BINARY_DOWNLOAD.search(line)
        ]
        if downloads:
            findings.append(
                Finding(
                    rule_id="install.dockerfile_binary_download",
                    area=Area.INSTALLATION,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title="Dockerfile downloads an executable from a URL",
                    explanation=(
                        "A binary fetched at build time is code you cannot review in the "
                        "repository. Unless it is pinned by digest, the image can change "
                        "without the Dockerfile changing."
                    ),
                    evidence=downloads[:4],
                    remediation="Pin by checksum, or install from a distribution package repository.",
                )
            )
    return findings
