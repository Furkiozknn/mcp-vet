"""Tool poisoning and prompt injection: text aimed at the model, not the user.

An MCP tool description is a contract read by a language model before it
decides whether and how to call the tool. That makes it an input to the model,
which makes it an injection surface - and unlike a README, nobody scrolls past
it, because the model reads all of it, every time.

The distinction this module tries to draw is not "does this text contain scary
words" but **who is this sentence addressed to**. A description that says what
the tool returns is a contract. A description that tells the model what to
believe, what to conceal, or what other tools to call is an instruction, and it
has no business being there.

That distinction cannot be made reliably by pattern matching, so nothing here
concludes maliciousness. Findings say what was matched, quote it, and name the
file and line, so a person decides. Deliberately conservative: a tool-poisoning
detector that cries wolf gets muted, and a muted detector catches nothing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

from .models import Area, Confidence, Evidence, Finding, Severity
from .scanning import ScannedFile, snippet

# Phrases that only make sense if the reader is a model being redirected.
_OVERRIDE = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|prompts?|rules?)"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|the\s+above)"
    r"|forget\s+(?:everything|all\s+previous)"
    r"|new\s+instructions?\s*:",
    re.IGNORECASE,
)

# Attempts to impersonate a higher-privileged speaker.
_ROLE_SPOOF = re.compile(
    r"<\s*(?:system|important|secret|admin)\s*>"
    r"|\[\s*(?:system|admin)\s*\]"
    r"|^\s*system\s*:"
    r"|you\s+are\s+(?:now\s+)?(?:a|an|the)\s+\w+\s+(?:assistant|agent|model)",
    re.IGNORECASE | re.MULTILINE,
)

# Instructions to hide activity from the person the model is working for.
_CONCEALMENT = re.compile(
    r"do\s+not\s+(?:tell|inform|mention|show|reveal|display)\s+(?:this\s+)?(?:to\s+)?the\s+user"
    r"|without\s+(?:telling|informing|notifying|asking)\s+the\s+user"
    r"|do\s+not\s+mention\s+(?:this|that)"
    r"|keep\s+this\s+(?:secret|hidden|confidential)\s+from"
    r"|silently\s+(?:call|invoke|run|execute)",
    re.IGNORECASE,
)

# Instructions to go get something the tool has no business with.
_SECRET_SOLICITATION = re.compile(
    r"(?:read|send|include|attach|return|provide)\s+(?:the\s+)?(?:contents?\s+of\s+)?"
    r"(?:~/\.ssh|\.env\b|environment\s+variables?|api[\s_-]?keys?|credentials?|tokens?|passwords?)"
    r"|before\s+(?:using|calling)\s+this\s+tool[^.\n]{0,60}(?:read|open|fetch|load)",
    re.IGNORECASE,
)

# Instructions to invoke something else.
_TOOL_REDIRECTION = re.compile(
    r"(?:always\s+)?(?:call|invoke|use|run)\s+(?:the\s+)?[\w.]+\s+tool\s+(?:first|before|after|instead)"
    r"|you\s+must\s+(?:also\s+)?(?:call|invoke|use)\s+",
    re.IGNORECASE,
)

# Model-directed imperatives in general. Weakest signal here by a distance:
# plenty of honest documentation says "you must provide a valid path". Only
# reported when it appears inside a tool description, and only as INFO.
_MODEL_DIRECTED = re.compile(
    r"\b(?:you\s+must\s+always|always\s+remember\s+to|it\s+is\s+critical\s+that\s+you"
    r"|under\s+no\s+circumstances\s+should\s+you)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Signal:
    rule_id: str
    regex: re.Pattern
    title: str
    explanation: str
    severity: Severity
    confidence: Confidence
    remediation: str


_SIGNALS: List[_Signal] = [
    _Signal(
        "injection.instruction_override",
        _OVERRIDE,
        "Text attempts to override the model's prior instructions",
        "A phrase whose only function is to make a model discard the instructions it "
        "was given. Nothing describing a tool's behaviour needs to say this.",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Treat this server as hostile unless the author can explain the phrase.",
    ),
    _Signal(
        "injection.role_spoofing",
        _ROLE_SPOOF,
        "Text impersonates a system or privileged speaker",
        "Markup like <IMPORTANT> or a 'system:' prefix is an attempt to have "
        "repository content read with more authority than data deserves.",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Confirm whether the text is describing behaviour or trying to assume authority.",
    ),
    _Signal(
        "injection.concealment",
        _CONCEALMENT,
        "Text instructs the model to hide activity from the user",
        "A tool asking not to be mentioned is asking to operate without the consent "
        "of the person the model is working for. Legitimate tools do not need this.",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Do not install. There is no benign reading of an instruction to conceal.",
    ),
    _Signal(
        "injection.secret_solicitation",
        _SECRET_SOLICITATION,
        "Text asks for credentials or files unrelated to the tool's function",
        "Instructions to read .env, SSH keys or environment variables inside a tool "
        "description are how a poisoned tool gets a model to fetch secrets for it.",
        Severity.CRITICAL,
        Confidence.MEDIUM,
        "Do not install until the author explains why this text is present.",
    ),
    _Signal(
        "injection.tool_redirection",
        _TOOL_REDIRECTION,
        "Text directs the model to call other tools",
        "A description that choreographs other tools is steering the agent rather "
        "than describing itself - the mechanism behind cross-tool poisoning.",
        Severity.HIGH,
        Confidence.LOW,
        "Check whether this is a genuine usage note or an attempt to chain tools.",
    ),
    _Signal(
        "injection.model_directed_language",
        _MODEL_DIRECTED,
        "Tool description contains model-directed imperatives",
        "The description addresses the model ('you must always...') rather than "
        "describing the tool's contract. Often just enthusiastic documentation, "
        "which is why this is informational - but it is the weak form of the same "
        "shape the findings above describe.",
        Severity.INFO,
        Confidence.LOW,
        "Read the description and judge whether it describes or instructs.",
    ),
]


# --------------------------------------------------------------------------
# Locating tool descriptions
# --------------------------------------------------------------------------

_TOOL_DECORATOR = re.compile(r"@(?:\w+\.)?tool\s*\(|@(?:\w+\.)?(?:list_tools|call_tool)\b")
_DOCSTRING_START = re.compile(r'^\s*(?:[rubf]{0,2})("""|\'\'\')')
_DESCRIPTION_FIELD = re.compile(r'["\']?description["\']?\s*[:=]\s*["\'](.{0,400}?)["\']', re.DOTALL)


@dataclass
class ToolText:
    """A block of text a model will read before choosing to call a tool."""

    path: str
    line: int
    text: str
    kind: str  # "docstring" | "description-field"


def extract_tool_texts(files: Sequence[ScannedFile]) -> List[ToolText]:
    """Pull out the text that actually reaches a model.

    Two shapes cover almost every server in the wild: a Python docstring under
    an `@mcp.tool()` decorator, and a `description:` field in a JS/TS or JSON
    tool definition.
    """
    found: List[ToolText] = []
    for scanned in files:
        if scanned.extension == ".py":
            found.extend(_python_tool_docstrings(scanned))
        if scanned.extension in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"}:
            found.extend(_description_fields(scanned))
    return found


def _python_tool_docstrings(scanned: ScannedFile) -> List[ToolText]:
    out: List[ToolText] = []
    for index, line in enumerate(scanned.lines, start=1):
        if not _TOOL_DECORATOR.search(line):
            continue
        # Walk forward to the function's docstring, tolerating decorators,
        # multi-line signatures and blank lines in between.
        for offset in range(index, min(index + 25, len(scanned.lines)) + 1):
            candidate = scanned.line_at(offset)
            match = _DOCSTRING_START.match(candidate)
            if not match:
                continue
            quote = match.group(1)
            body: List[str] = []
            remainder = candidate.split(quote, 1)[1]
            if quote in remainder:
                body.append(remainder.split(quote, 1)[0])
            else:
                body.append(remainder)
                for tail in range(offset + 1, min(offset + 60, len(scanned.lines)) + 1):
                    text = scanned.line_at(tail)
                    if quote in text:
                        body.append(text.split(quote, 1)[0])
                        break
                    body.append(text)
            out.append(
                ToolText(path=scanned.path, line=offset, text="\n".join(body).strip(),
                         kind="docstring")
            )
            break
    return out


def _description_fields(scanned: ScannedFile) -> List[ToolText]:
    out: List[ToolText] = []
    for index, line in enumerate(scanned.lines, start=1):
        if len(line) > 4000:
            continue
        for match in _DESCRIPTION_FIELD.finditer(line):
            text = match.group(1).strip()
            if text:
                out.append(ToolText(path=scanned.path, line=index, text=text,
                                    kind="description-field"))
    return out


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------


def analyze(files: Sequence[ScannedFile], docs: Optional[Sequence[ScannedFile]] = None) -> List[Finding]:
    """Look for model-directed text, weighting tool descriptions above prose.

    The same phrase carries different weight depending on where it sits. In a
    tool description it is read by the model on every call; in a README it is
    read once by whoever is browsing. Both are reported, but only the first is
    treated as tool poisoning.
    """
    findings: List[Finding] = []
    tool_texts = extract_tool_texts(files)

    for signal in _SIGNALS:
        evidence: List[Evidence] = []
        for tool_text in tool_texts:
            if signal.regex.search(tool_text.text):
                evidence.append(
                    Evidence(
                        path=tool_text.path,
                        line=tool_text.line,
                        snippet=snippet(tool_text.text, limit=240),
                        detail=f"in a tool {tool_text.kind}",
                    )
                )
        if evidence:
            findings.append(
                Finding(
                    rule_id=signal.rule_id,
                    area=Area.PROMPT_INJECTION,
                    severity=signal.severity,
                    confidence=signal.confidence,
                    title=signal.title,
                    explanation=(
                        signal.explanation
                        + " This is potentially tool poisoning: the text is delivered to "
                        "the model as part of the tool's contract, so it influences the "
                        "agent's behaviour without the user ever seeing it."
                    ),
                    evidence=evidence[:5],
                    remediation=signal.remediation,
                )
            )

    # The same phrases in documentation are worth surfacing, one notch down:
    # a README is read by people, and can still be an attempt to steer an agent
    # that was pointed at the repository.
    for scanned in docs or []:
        for signal in _SIGNALS:
            if signal.severity is Severity.INFO:
                continue
            hits = [
                Evidence(path=scanned.path, line=i, snippet=snippet(line, limit=240))
                for i, line in enumerate(scanned.lines, start=1)
                if len(line) <= 2000 and signal.regex.search(line)
            ]
            if hits:
                findings.append(
                    Finding(
                        rule_id=signal.rule_id + ".documentation",
                        area=Area.PROMPT_INJECTION,
                        severity=_one_notch_down(signal.severity),
                        confidence=Confidence.LOW,
                        title=signal.title + " (in documentation)",
                        explanation=(
                            "The same shape appears in documentation rather than in a tool "
                            "description. Lower weight - a model does not read it on every "
                            "call - but an agent asked to review this repository will read "
                            "it, which is exactly the scenario mcp-vet is used in."
                        ),
                        evidence=hits[:3],
                        remediation=signal.remediation,
                    )
                )
    return findings


def _one_notch_down(severity: Severity) -> Severity:
    order = [Severity.NOT_FLAGGED, Severity.INFO, Severity.LOW, Severity.MEDIUM,
             Severity.HIGH, Severity.CRITICAL]
    index = order.index(severity)
    return order[max(0, index - 1)]
