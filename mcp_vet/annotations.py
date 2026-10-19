"""Tool annotations that contradict the code behind them.

MCP lets a server attach behaviour hints to each tool (spec 2025-03-26 and
later): `readOnlyHint` says the tool "does not modify its environment",
`destructiveHint: false` says it performs only additive updates. The spec
calls these hints untrusted, but clients use them. A client may skip the
confirmation prompt for a read-only tool, or group it with harmless ones. A
tool that declares itself read-only and then runs a shell command has told the
model and the user something false, and in a way that removes a safeguard.

What this module checks is narrow on purpose. It looks for a **literal** claim
(`readOnlyHint=True`, `read_only_hint=True`, `"readOnlyHint": true`,
`destructiveHint: false`), attached to one tool, and asks whether that tool's
own code reaches for a capability the claim rules out. Annotations computed at
run time (`read_only_hint=not cap.writes_files`) are not literal claims and are
not judged: there is nothing static to contradict.

Scope is where the confidence comes from:

* **Python** - the claim sits in the decorator (`@mcp.tool(annotations=...)`),
  directly or through a module-level constant (`READ_ONLY =
  ToolAnnotations(readOnlyHint=True)`). The tool's body is the decorated
  function, bounded by indentation. MEDIUM confidence.
* **JavaScript / TypeScript** - the claim sits in a `registerTool(...)` /
  `.tool(...)` call, and the body is everything up to the next tool
  registration. A handler defined elsewhere is missed, and a helper defined
  between two registrations is counted against the first. LOW confidence.

Only capabilities on a line that is real code count: a mention inside a
comment, a docstring or a denylist (`Match.context`) does not contradict a
read-only claim.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .models import Area, Confidence, Evidence, Finding, Severity
from .scanning import ScannedFile, snippet

_PY_EXTENSIONS = {".py"}
_JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"}

_READ_ONLY_TRUE = re.compile(
    r"""(?:\breadOnlyHint\b|\bread_only_hint\b|["']readOnlyHint["'])\s*[=:]\s*(?:True|true)\b"""
)
_DESTRUCTIVE_FALSE = re.compile(
    r"""(?:\bdestructiveHint\b|\bdestructive_hint\b|["']destructiveHint["'])\s*[=:]\s*(?:False|false)\b"""
)

_PY_TOOL_DECORATOR = re.compile(r"^\s*@(?:[\w.]+\.)?tool\s*\(")
_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+\w+")
_PY_CONSTANT = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*=\s*(?:[\w.]*ToolAnnotations\s*\(|\{)")
_JS_TOOL_START = re.compile(r"\.(?:registerTool|tool)\s*\(|\bregisterTool\s*\(")

# What a read-only tool may not do, and what a non-destructive one may not.
_NOT_READ_ONLY = {
    "shell.execute": Severity.HIGH,
    "process.spawn": Severity.HIGH,
    "code.eval": Severity.HIGH,
    "code.remote_execution": Severity.HIGH,
    "filesystem.delete": Severity.HIGH,
    "filesystem.chmod": Severity.HIGH,
    "persistence.scheduler": Severity.HIGH,
    "persistence.startup": Severity.HIGH,
    "package.install": Severity.HIGH,
    "filesystem.write": Severity.MEDIUM,
}
_DESTRUCTIVE = {
    "filesystem.delete": Severity.HIGH,
    "shell.execute": Severity.MEDIUM,
}

MAX_JS_SEGMENT_LINES = 200


@dataclass
class ToolClaim:
    path: str
    line: int          # where the claim is written
    claim: str         # "read-only" | "non-destructive"
    body: Tuple[int, int]  # inclusive line range of the tool's code
    confidence: Confidence


def _py_constants(scanned: ScannedFile) -> Dict[str, Set[str]]:
    """Module-level annotation constants and the claims they make."""
    constants: Dict[str, Set[str]] = {}
    lines = scanned.lines
    for index, line in enumerate(lines):
        match = _PY_CONSTANT.match(line)
        if not match:
            continue
        # The constructor may span lines; read until the brackets balance.
        text, depth = "", 0
        for tail in lines[index:index + 15]:
            text += tail + "\n"
            depth += tail.count("(") + tail.count("{") - tail.count(")") - tail.count("}")
            if depth <= 0:
                break
        claims = set()
        if _READ_ONLY_TRUE.search(text):
            claims.add("read-only")
        if _DESTRUCTIVE_FALSE.search(text):
            claims.add("non-destructive")
        if claims:
            constants[match.group(1)] = claims
    return constants


def _py_claims(scanned: ScannedFile) -> List[ToolClaim]:
    constants = _py_constants(scanned)
    lines = scanned.lines
    claims: List[ToolClaim] = []
    index = 0
    while index < len(lines):
        if not _PY_TOOL_DECORATOR.match(lines[index]):
            index += 1
            continue
        start = index
        def_index: Optional[int] = None
        for probe in range(index, min(index + 30, len(lines))):
            if _PY_DEF.match(lines[probe]):
                def_index = probe
                break
        if def_index is None:
            index += 1
            continue
        header = "\n".join(lines[start:def_index])
        found: Set[str] = set()
        if _READ_ONLY_TRUE.search(header):
            found.add("read-only")
        if _DESTRUCTIVE_FALSE.search(header):
            found.add("non-destructive")
        for name, constant_claims in constants.items():
            if re.search(r"\b" + re.escape(name) + r"\b", header):
                found |= constant_claims
        indent = len(_PY_DEF.match(lines[def_index]).group(1))
        end = def_index
        for probe in range(def_index + 1, len(lines)):
            text = lines[probe]
            if not text.strip():
                continue
            if len(text) - len(text.lstrip()) <= indent:
                break
            end = probe
        claim_line = start + 1
        for offset, text in enumerate(lines[start:def_index], start=start + 1):
            if _READ_ONLY_TRUE.search(text) or _DESTRUCTIVE_FALSE.search(text) or any(
                re.search(r"\b" + re.escape(n) + r"\b", text) for n in constants
            ):
                claim_line = offset
                break
        for claim in sorted(found):
            claims.append(ToolClaim(scanned.path, claim_line, claim,
                                    (def_index + 1, end + 1), Confidence.MEDIUM))
        index = def_index + 1
    return claims


def _js_claims(scanned: ScannedFile) -> List[ToolClaim]:
    lines = scanned.lines
    starts = [i for i, line in enumerate(lines) if _JS_TOOL_START.search(line)]
    claims: List[ToolClaim] = []
    for position, start in enumerate(starts):
        stop = starts[position + 1] if position + 1 < len(starts) else len(lines)
        stop = min(stop, start + MAX_JS_SEGMENT_LINES)
        segment = lines[start:stop]
        for claim, regex in (("read-only", _READ_ONLY_TRUE), ("non-destructive", _DESTRUCTIVE_FALSE)):
            for offset, text in enumerate(segment):
                if regex.search(text):
                    claims.append(ToolClaim(scanned.path, start + offset + 1, claim,
                                            (start + 1, stop), Confidence.LOW))
                    break
    return claims


def extract_claims(files: Sequence[ScannedFile]) -> List[ToolClaim]:
    claims: List[ToolClaim] = []
    for scanned in files:
        if scanned.extension in _PY_EXTENSIONS:
            claims.extend(_py_claims(scanned))
        elif scanned.extension in _JS_EXTENSIONS:
            claims.extend(_js_claims(scanned))
    return claims


_RULES = {
    "read-only": (
        "annotations.read_only_contradicted",
        "Tool is annotated read-only but its code {verb}",
        "The tool declares readOnlyHint (it 'does not modify its environment'), and "
        "its own body reaches for {caps}. Clients may skip the confirmation prompt "
        "for a read-only tool, so a false claim removes the one check a user had "
        "before the call ran.",
        _NOT_READ_ONLY,
    ),
    "non-destructive": (
        "annotations.non_destructive_contradicted",
        "Tool is annotated non-destructive but its code {verb}",
        "The tool declares destructiveHint: false (only additive updates), and its "
        "own body reaches for {caps}. A client that trusts the hint will not warn "
        "before an irreversible call.",
        _DESTRUCTIVE,
    ),
}


def _verb(capabilities: Sequence[str]) -> str:
    if any(c.startswith(("shell.", "process.", "code.")) for c in capabilities):
        return "runs commands or code"
    if "filesystem.delete" in capabilities:
        return "deletes files"
    if "filesystem.write" in capabilities:
        return "writes files"
    return "changes the system"


def analyze(files: Sequence[ScannedFile], matches: Sequence) -> List[Finding]:
    """One finding per contradicted claim kind, with the claim and the code as evidence."""
    claims = extract_claims(files)
    if not claims:
        return []
    by_path: Dict[str, List] = {}
    for match in matches:
        if match.context in ("prose", "exclusion") or not match.rule.capability:
            continue
        by_path.setdefault(match.file.path, []).append(match)

    grouped: Dict[str, List[Tuple[ToolClaim, List]]] = {}
    for claim in claims:
        allowed = _RULES[claim.claim][3]
        first, last = claim.body
        hits = [m for m in by_path.get(claim.path, [])
                if first <= m.line <= last and m.rule.capability in allowed]
        if hits:
            grouped.setdefault(claim.claim, []).append((claim, hits))

    findings: List[Finding] = []
    for kind, pairs in grouped.items():
        rule_id, title, explanation, table = _RULES[kind]
        capabilities = sorted({m.rule.capability for _, hits in pairs for m in hits})
        severity = max((table[c] for c in capabilities), key=lambda s: s.rank)
        confidence = (Confidence.MEDIUM
                      if any(c.confidence is Confidence.MEDIUM for c, _ in pairs)
                      else Confidence.LOW)
        evidence: List[Evidence] = []
        for claim, hits in pairs[:4]:
            evidence.append(Evidence(path=claim.path, line=claim.line,
                                     detail=f"{claim.claim} claim"))
            for match in hits[:2]:
                evidence.append(Evidence(path=match.file.path, line=match.line,
                                         snippet=snippet(match.text),
                                         detail=match.rule.capability))
        findings.append(Finding(
            rule_id=rule_id,
            area=Area.CAPABILITIES,
            severity=severity,
            confidence=confidence,
            title=title.format(verb=_verb(capabilities)),
            explanation=explanation.format(caps=", ".join(capabilities))
            + f" ({len(pairs)} tool(s).)",
            evidence=evidence,
            remediation="Drop the hint, or move the side effect out of the tool. "
                        "Treat every call of this tool as one that changes the system.",
        ))
    return findings
