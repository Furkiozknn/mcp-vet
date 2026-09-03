"""Central data model for an mcp-vet audit.

Everything the analyzers produce lands in one of these types, and every
renderer reads only from them. That split is what keeps the text report, the
JSON report and the exit code from drifting apart: they are three views of one
`AuditReport`, not three separate opinions.

Two design rules are load-bearing here.

**Severity is not confidence.** A pattern match can be high severity and low
confidence at the same time - `subprocess` with a variable argument really
would be arbitrary command execution *if* the variable is attacker-controlled,
and static matching cannot tell. Collapsing the two into one number is how
scanners end up either crying wolf or staying quiet about real problems, so
they stay separate all the way to the output.

**A finding without evidence is an opinion.** Every `Finding` carries the file
and line it came from and the snippet that triggered it, so a reader can
disagree with the tool by looking at the same thing it looked at.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

# Bumped when the JSON output's shape changes in a way a consumer could
# notice. Documented in docs/json-schema.md.
SCHEMA_VERSION = "1.0"


class Severity(Enum):
    """How bad this would be if the finding is real.

    NOT_FLAGGED exists so a report can say "we looked and found nothing" in the
    same vocabulary it uses for everything else. It is deliberately *not*
    called SAFE: mcp-vet never concludes that something is safe, only that a
    given check did not fire.
    """

    NOT_FLAGGED = "NOT_FLAGGED"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_ORDER = {
    Severity.NOT_FLAGGED: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class Confidence(Enum):
    """How sure we are that the finding is what it looks like.

    LOW does not mean "probably wrong" - it means static analysis alone cannot
    settle it and a human has to look. Findings are never dropped for low
    confidence; they are reported with it attached.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[self.value]


class Status(Enum):
    """Whether a check actually ran, and why not if it didn't.

    An analysis that could not run must never render as a clean result. These
    four states keep "we checked and found nothing" distinct from "we could not
    check", which is the difference between evidence and silence.
    """

    VERIFIED = "VERIFIED"          # the check ran against real data
    UNAVAILABLE = "UNAVAILABLE"    # the data source could not be reached
    NOT_APPLICABLE = "NOT_APPLICABLE"  # nothing here to check
    NOT_CHECKED = "NOT_CHECKED"    # deliberately skipped (e.g. --offline)


class Area(Enum):
    """The independent dimensions a server is assessed on.

    Deliberately not summed into a single number. A server can be perfectly
    maintained, widely starred and still exfiltrate your environment - one
    score would average that away.
    """

    POPULARITY_INTEGRITY = "popularity_integrity"
    REPOSITORY_TRUST = "repository_trust"
    SOURCE_CODE = "source_code"
    DEPENDENCIES = "dependencies"
    INSTALLATION = "installation"
    CAPABILITIES = "capabilities"
    NETWORK = "network"
    PROMPT_INJECTION = "prompt_injection"
    MAINTENANCE = "maintenance"
    PROVENANCE = "provenance"


@dataclass
class Evidence:
    """Where a finding came from. Without this a finding is unfalsifiable."""

    path: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Finding:
    """One thing worth a reader's attention, with its receipts."""

    area: Area
    severity: Severity
    confidence: Confidence
    title: str
    explanation: str
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None
    # Stable machine-readable identifier, e.g. "source.subprocess_shell_true".
    # Consumers should key off this rather than the human-readable title.
    rule_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "area": self.area.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "explanation": self.explanation,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
        }


@dataclass
class Capability:
    """Something the server can do to the machine it runs on."""

    name: str            # dotted, e.g. "shell.execute", "filesystem.write"
    description: str
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
        }


class EndpointClass(Enum):
    EXPECTED = "EXPECTED"        # plausibly part of the stated purpose
    UNEXPLAINED = "UNEXPLAINED"  # real host, no obvious relation to the purpose
    SUSPICIOUS = "SUSPICIOUS"    # shape or context is a problem on its own
    INFRASTRUCTURE = "INFRASTRUCTURE"  # package registries, CI, docs


@dataclass
class NetworkEndpoint:
    host: str
    classification: EndpointClass
    reason: str
    scheme: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "scheme": self.scheme,
            "classification": self.classification.value,
            "reason": self.reason,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class CredentialRequirement:
    """A secret the server expects, and what it would cost if it leaked.

    Only the *name* of the variable is ever recorded. mcp-vet does not read
    credential values, and nothing in this type is capable of carrying one.
    """

    name: str
    required: bool
    source: str          # "environment", "config", "argument", "registry"
    blast_radius: str    # plain-language consequence if compromised
    sent_externally: bool = False
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "required": self.required,
            "source": self.source,
            "blast_radius": self.blast_radius,
            "sent_externally": self.sent_externally,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class DataFlow:
    """A source -> transformation -> sink chain found inside one file.

    "requests is imported" is close to useless on its own. "os.environ is read
    on line 12 and an outbound POST happens on line 19 of the same file" is
    something a reader can actually act on. This type only claims co-location
    and ordering, never proven taint - `confidence` carries that caveat.
    """

    source: str
    sink: str
    destination: Optional[str]
    confidence: Confidence
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "sink": self.sink,
            "destination": self.destination,
            "confidence": self.confidence.value,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class AreaAssessment:
    """One dimension's verdict, plus whether it was actually assessable."""

    area: Area
    severity: Severity
    status: Status
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "area": self.area.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "summary": self.summary,
        }


@dataclass
class AuditReport:
    """Everything one audit produced. The only thing renderers read."""

    target: str
    schema_version: str = SCHEMA_VERSION
    source_url: Optional[str] = None
    version: Optional[str] = None
    overall: Severity = Severity.NOT_FLAGGED
    areas: List[AreaAssessment] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    capabilities: List[Capability] = field(default_factory=list)
    endpoints: List[NetworkEndpoint] = field(default_factory=list)
    credentials: List[CredentialRequirement] = field(default_factory=list)
    dataflows: List[DataFlow] = field(default_factory=list)
    recommendation: str = ""
    limitations: List[str] = field(default_factory=list)
    # Free-form context a renderer may show but never scores on, e.g. raw
    # popularity numbers or which analyses were skipped.
    notes: Dict[str, Any] = field(default_factory=dict)

    def area(self, area: Area) -> Optional[AreaAssessment]:
        for assessment in self.areas:
            if assessment.area is area:
                return assessment
        return None

    def sorted_findings(self) -> List[Finding]:
        """Most severe first; ties broken by confidence, then by rule id.

        Sorting by rule id last keeps output byte-stable across runs, which
        matters for diffing two reports in CI.
        """
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, -f.confidence.rank, f.rule_id, f.title),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "source_url": self.source_url,
            "version": self.version,
            "overall": self.overall.value,
            "recommendation": self.recommendation,
            "areas": [a.to_dict() for a in self.areas],
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "capabilities": [c.to_dict() for c in self.capabilities],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "credentials": [c.to_dict() for c in self.credentials],
            "dataflows": [d.to_dict() for d in self.dataflows],
            "limitations": self.limitations,
            "notes": self.notes,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False, ensure_ascii=False)
