"""Static analysis of a server's own source: what it can do, and to whom.

Running the pattern catalogue is the easy half. The half that produces
something worth reading is correlation:

* "requests is imported" is close to noise. "os.environ is read on line 12 and
  an outbound POST happens on line 19 of the same file" is a lead.
* A single INFO match is not worth a reader's attention. Twenty INFO matches
  that together describe a server which reads your environment, your files and
  talks to an undocumented host are worth quite a lot.

So this module reports individual findings *and* the combinations, and it is
explicit that a combination is co-location, never proven taint. Static
matching cannot follow a value; claiming otherwise would be the kind of false
precision that teaches people to ignore the tool.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import (
    Area,
    Capability,
    Confidence,
    CredentialRequirement,
    DataFlow,
    Evidence,
    Finding,
    Severity,
)
from .patterns import ROLE_EXEC, ROLE_SINK, ROLE_SOURCE, Rule, rules_for
from .scanning import ScannedFile, snippet

# At most this many evidence lines per finding: enough to show the pattern is
# not a one-off, few enough that a report stays readable.
MAX_EVIDENCE_PER_FINDING = 5

# A source and a sink this many lines apart in one file are close enough to be
# worth pointing at. Wider than a typical function, narrower than a module.
FLOW_PROXIMITY_LINES = 40

MAX_FLOWS_REPORTED = 12


@dataclass
class Match:
    rule: Rule
    file: ScannedFile
    line: int
    text: str


# --------------------------------------------------------------------------
# Running the catalogue
# --------------------------------------------------------------------------


def scan_matches(files: Sequence[ScannedFile]) -> List[Match]:
    """Apply every applicable rule to every line of every file."""
    matches: List[Match] = []
    for scanned in files:
        applicable = rules_for(scanned.extension)
        if not applicable:
            continue
        for index, line in enumerate(scanned.lines, start=1):
            # Cheap guard: a single enormous line is minified or generated, and
            # matching 30 patterns against it repeatedly buys nothing.
            if len(line) > 2000:
                continue
            for rule in applicable:
                if rule.regex.search(line):
                    matches.append(Match(rule=rule, file=scanned, line=index, text=line))
    return matches


def matches_to_findings(matches: Sequence[Match]) -> List[Finding]:
    """Collapse many matches of one rule into one finding with several receipts."""
    grouped: Dict[str, List[Match]] = defaultdict(list)
    for match in matches:
        grouped[match.rule.rule_id].append(match)

    findings: List[Finding] = []
    for rule_id, group in grouped.items():
        rule = group[0].rule
        if rule.informational_only:
            # These describe capabilities rather than problems; they surface in
            # the capability list and in combinations, not as standalone noise.
            continue
        evidence = [
            Evidence(path=m.file.path, line=m.line, snippet=snippet(m.text))
            for m in group[:MAX_EVIDENCE_PER_FINDING]
        ]
        extra = len(group) - len(evidence)
        explanation = rule.explanation
        if extra > 0:
            explanation += f" ({extra} further occurrence{'s' if extra != 1 else ''} not listed.)"
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                area=rule.area,
                severity=rule.severity,
                confidence=rule.confidence,
                title=rule.title,
                explanation=explanation,
                evidence=evidence,
                remediation=rule.remediation,
            )
        )
    return findings


def matches_to_capabilities(matches: Sequence[Match]) -> List[Capability]:
    """What the code demonstrably reaches for, with a line for each claim."""
    by_capability: Dict[str, List[Match]] = defaultdict(list)
    for match in matches:
        if match.rule.capability:
            by_capability[match.rule.capability].append(match)

    capabilities: List[Capability] = []
    for name, group in sorted(by_capability.items()):
        capabilities.append(
            Capability(
                name=name,
                description=group[0].rule.title,
                evidence=[
                    Evidence(path=m.file.path, line=m.line, snippet=snippet(m.text))
                    for m in group[:3]
                ],
            )
        )
    return capabilities


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

_ENV_NAME_PATTERNS = [
    re.compile(r"os\.environ\s*\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"os\.environ\.get\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"os\.getenv\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"process\.env\s*\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"),
    re.compile(r"getenv\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"),
]

# Names that look like they hold a secret rather than a setting.
_SECRETISH = re.compile(
    r"TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|SESSION|COOKIE|DSN|WEBHOOK",
    re.IGNORECASE,
)

# Blast radius for credentials whose scope is widely understood. Anything not
# listed gets an honest generic answer rather than an invented one.
_KNOWN_BLAST_RADIUS = {
    "GITHUB_TOKEN": "Inherits every permission the token was issued with - typically read/write across your repositories, and organisation access if it is a classic token.",
    "GH_TOKEN": "Same as GITHUB_TOKEN: whatever scopes the token carries.",
    "AWS_SECRET_ACCESS_KEY": "Grants whatever the IAM principal can do, which is frequently far more than one service.",
    "AWS_ACCESS_KEY_ID": "Pairs with the secret key to authenticate as an IAM principal.",
    "OPENAI_API_KEY": "Billable API access on your account, and read access to anything the key's project can reach.",
    "ANTHROPIC_API_KEY": "Billable API access on your account.",
    "SLACK_TOKEN": "Read and post access to whatever channels the token's scopes cover.",
    "DISCORD_TOKEN": "Full bot access to every guild the bot has joined.",
    "DATABASE_URL": "Direct database access, usually including credentials embedded in the URL.",
    "STRIPE_SECRET_KEY": "Live payment operations on your account.",
    "NPM_TOKEN": "Publish rights to your npm packages - a supply-chain credential.",
}


def extract_credentials(files: Sequence[ScannedFile]) -> List[CredentialRequirement]:
    """Find which named secrets the server expects.

    Only variable *names* are ever collected. Nothing here reads a value, and
    the returned type has nowhere to put one.
    """
    seen: Dict[str, CredentialRequirement] = {}
    for scanned in files:
        for index, line in enumerate(scanned.lines, start=1):
            if len(line) > 2000:
                continue
            for pattern in _ENV_NAME_PATTERNS:
                for name in pattern.findall(line):
                    if not _SECRETISH.search(name):
                        continue
                    if name in seen:
                        continue
                    # A `.get(...)` or a defaulted lookup reads as optional;
                    # a bare subscript raises when absent, so it is required.
                    optional = ".get(" in line or "getenv(" in line
                    seen[name] = CredentialRequirement(
                        name=name,
                        required=not optional,
                        source="environment",
                        blast_radius=_KNOWN_BLAST_RADIUS.get(
                            name,
                            "Scope unknown to mcp-vet. Assume it grants everything the "
                            "issuing service allows until you have checked.",
                        ),
                        evidence=[
                            Evidence(path=scanned.path, line=index, snippet=snippet(line))
                        ],
                    )
    return [seen[k] for k in sorted(seen)]


# --------------------------------------------------------------------------
# Data-flow correlation
# --------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://([A-Za-z0-9._~-]+(?::\d+)?)(/[^\s'\"<>)\]]*)?")


def _nearest_url(scanned: ScannedFile, line: int, window: int = FLOW_PROXIMITY_LINES) -> Optional[str]:
    """The closest literal URL host to a given line, if any is nearby."""
    best: Optional[Tuple[int, str]] = None
    low, high = max(1, line - window), min(len(scanned.lines), line + window)
    for index in range(low, high + 1):
        match = _URL_RE.search(scanned.line_at(index))
        if match:
            distance = abs(index - line)
            if best is None or distance < best[0]:
                best = (distance, match.group(1))
    return best[1] if best else None


def detect_dataflows(matches: Sequence[Match]) -> List[DataFlow]:
    """Pair sensitive reads with outbound sends that sit near them.

    This reports *proximity*, which is the honest limit of line-based analysis.
    A chain here means "these two things happen close together in one file, go
    look" - not "this value provably reaches that call". Confidence carries
    that: MEDIUM when they sit within a function's worth of lines, LOW when
    they merely share a file.
    """
    by_file: Dict[str, List[Match]] = defaultdict(list)
    for match in matches:
        if match.rule.role in (ROLE_SOURCE, ROLE_SINK, ROLE_EXEC):
            by_file[match.file.path].append(match)

    flows: List[DataFlow] = []
    for path, group in sorted(by_file.items()):
        sources = [m for m in group if m.rule.role == ROLE_SOURCE]
        sinks = [m for m in group if m.rule.role in (ROLE_SINK, ROLE_EXEC)]
        if not sources or not sinks:
            continue

        # One flow per (source rule, sink rule) pair per file, using the
        # closest instance - otherwise a file with ten env reads and ten posts
        # produces a hundred near-identical rows.
        best_pairs: Dict[Tuple[str, str], Tuple[int, Match, Match]] = {}
        for src in sources:
            for sink in sinks:
                key = (src.rule.rule_id, sink.rule.rule_id)
                distance = abs(src.line - sink.line)
                current = best_pairs.get(key)
                if current is None or distance < current[0]:
                    best_pairs[key] = (distance, src, sink)

        for (distance, src, sink) in best_pairs.values():
            confidence = Confidence.MEDIUM if distance <= FLOW_PROXIMITY_LINES else Confidence.LOW
            # Only a network sink has a URL destination. Attaching the nearest
            # URL to a subprocess call would read as "this shell command sends
            # data to that host", which is not what was observed.
            destination = (
                _nearest_url(sink.file, sink.line)
                if (sink.rule.capability or "") in _OUTBOUND
                else None
            )
            flows.append(
                DataFlow(
                    source=src.rule.capability or src.rule.rule_id,
                    sink=sink.rule.capability or sink.rule.rule_id,
                    destination=destination,
                    confidence=confidence,
                    evidence=[
                        Evidence(path=path, line=src.line, snippet=snippet(src.text),
                                 detail="source"),
                        Evidence(path=path, line=sink.line, snippet=snippet(sink.text),
                                 detail="sink"),
                    ],
                )
            )

    # Closest pairs first: proximity is the whole signal, so the tightest
    # chains belong at the top.
    flows.sort(key=lambda f: (-f.confidence.rank, f.source, f.sink))
    return flows[:MAX_FLOWS_REPORTED]


# Source capabilities whose pairing with an outbound sink is worth a finding of
# its own rather than a row in a table.
_EXFIL_WORTHY = {
    "environment.read": (Severity.HIGH, "environment variables"),
    "credentials.ssh": (Severity.CRITICAL, "SSH key material"),
    "credentials.cloud": (Severity.CRITICAL, "cloud credentials"),
    "credentials.browser": (Severity.CRITICAL, "browser credential stores"),
    "credentials.netrc": (Severity.CRITICAL, ".netrc credentials"),
    "credentials.keychain": (Severity.CRITICAL, "OS keychain secrets"),
    "filesystem.read": (Severity.MEDIUM, "local files"),
}

_OUTBOUND = {"network.external", "network.socket", "network.dns"}


def dataflow_findings(flows: Sequence[DataFlow]) -> List[Finding]:
    """Promote the dangerous chains into first-class findings."""
    findings: List[Finding] = []
    for flow in flows:
        if flow.sink not in _OUTBOUND:
            continue
        entry = _EXFIL_WORTHY.get(flow.source)
        if not entry:
            continue
        severity, subject = entry
        destination = flow.destination or "a destination this analysis could not resolve"
        findings.append(
            Finding(
                rule_id=f"dataflow.{flow.source}__{flow.sink}",
                area=Area.NETWORK,
                severity=severity,
                # Deliberately never higher than MEDIUM: proximity is not taint.
                confidence=Confidence.MEDIUM if flow.confidence is Confidence.MEDIUM else Confidence.LOW,
                title=f"Possible exfiltration path: {subject} read near an outbound request",
                explanation=(
                    f"The same file reads {subject} and makes an outbound network call "
                    f"nearby ({destination}). mcp-vet matches text, so it cannot prove the "
                    "value read is the value sent - what it can say is that both halves of "
                    "an exfiltration path exist in one place, which is worth reading before "
                    "you hand this server a credential."
                ),
                evidence=list(flow.evidence),
                remediation=(
                    "Open the file and follow the value. If the read and the request are "
                    "unrelated, this is a false positive; if they are connected, confirm "
                    "the destination is one the server documents."
                ),
            )
        )
    return findings


def combination_findings(matches: Sequence[Match]) -> List[Finding]:
    """Pairs that are unremarkable alone and alarming together."""
    capabilities: Set[str] = {m.rule.capability for m in matches if m.rule.capability}
    findings: List[Finding] = []

    def evidence_for(capability: str) -> List[Evidence]:
        return [
            Evidence(path=m.file.path, line=m.line, snippet=snippet(m.text))
            for m in matches
            if m.rule.capability == capability
        ][:2]

    if "encoding.base64" in capabilities and "code.eval" in capabilities:
        findings.append(
            Finding(
                rule_id="combo.decode_then_execute",
                area=Area.SOURCE_CODE,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                title="Decodes encoded data and evaluates code in the same project",
                explanation=(
                    "Base64 decoding is ordinary and runtime evaluation is occasionally "
                    "justified, but together they are the standard shape of a payload "
                    "hidden from anyone reading the source. Confirm the decoded bytes are "
                    "not what gets executed."
                ),
                evidence=evidence_for("encoding.base64") + evidence_for("code.eval"),
                remediation="Read both call sites before running this server at all.",
            )
        )

    if "package.install" in capabilities and {"shell.execute", "process.spawn"} & capabilities:
        findings.append(
            Finding(
                rule_id="combo.runtime_package_install",
                area=Area.INSTALLATION,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title="Installs packages by shelling out at runtime",
                explanation=(
                    "Code that installs dependencies while running executes whatever the "
                    "registry serves at that moment - which is not what you reviewed, and "
                    "can change under you without the repository changing."
                ),
                evidence=evidence_for("package.install"),
                remediation="Dependencies belong in a manifest resolved at install time, not fetched during a tool call.",
            )
        )

    return findings
