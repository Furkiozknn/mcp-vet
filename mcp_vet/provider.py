"""Is a credential going to the provider it belongs to?

`source.detect_dataflows` pairs an environment read with an outbound call in
the same file, and an environment read next to an outbound call is rated HIGH.
That is right for the shape it was written for - a server that reads
`GITHUB_TOKEN` and posts it to a collector - and wrong for the most common
shape of all: a server that reads `GROQ_API_KEY` and calls Groq. voice-io-mcp
replaced a quota-free health check with one that spends real quota, only
because the honest version was rated HIGH by this tool.

Lowering the rating everywhere would throw away the true positive. This module
instead asks one narrow question per file, and answers "yes" only when every
part of it can be read from literals in the source:

1. **Every credential is named, and named for a provider.** Each secret-looking
   environment variable the file reads (`GROQ_API_KEY`, or a constant that is
   bound to that literal) must carry the name of a destination the file talks
   to. A bulk read (`dict(os.environ)`, `{**process.env}`) never qualifies, and
   neither does a name that is computed and cannot be traced to a literal.
2. **Every destination is resolved.** Each outbound call must name its URL as a
   literal, as a constant bound to one, or as an f-string that starts with such
   a constant; a litellm call must name its model as `provider/...` the same
   way. A URL that arrives as a parameter - a tool argument, say - is exactly
   where a secret goes somewhere nobody chose, so one such call anywhere in the
   file ends the question.
3. **Every destination is documented.** The provider (its name or its domain)
   appears in the repository's own documentation, so the reader was told where
   their data goes.
4. **Nothing on the list is suspicious.** A paste, tunnel or webhook-capture
   host, or a raw IP address, is never a provider.

When all four hold the pairing is still reported - with its file and line - but
at LOW, with the reason spelled out. When any one fails, nothing changes and
the finding stays HIGH. Like every other qualification in mcp-vet, it is
narrow on purpose: a quieter security tool has to show it did not go deaf.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .network import _INFRASTRUCTURE, _IP_LITERAL, _SUSPICIOUS_HOSTS, _registrable
from .scanning import ScannedFile, prose_lines

# litellm routes by the prefix of the model string. Only providers whose
# prefix is also a word a README would use are listed; an unknown prefix is
# simply not a resolved destination.
LITELLM_PROVIDERS: Dict[str, str] = {
    "openai": "api.openai.com",
    "anthropic": "api.anthropic.com",
    "groq": "api.groq.com",
    "mistral": "api.mistral.ai",
    "gemini": "generativelanguage.googleapis.com",
    "cerebras": "api.cerebras.ai",
    "cohere": "api.cohere.ai",
    "deepseek": "api.deepseek.com",
    "openrouter": "openrouter.ai",
    "together_ai": "api.together.xyz",
    "fireworks_ai": "api.fireworks.ai",
    "perplexity": "api.perplexity.ai",
    "xai": "api.x.ai",
    "nvidia_nim": "integrate.api.nvidia.com",
    "huggingface": "api-inference.huggingface.co",
    "replicate": "api.replicate.com",
    "sambanova": "api.sambanova.ai",
}

_LOOPBACK = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}

_SECRETISH = re.compile(
    r"TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|SESSION|COOKIE|DSN|WEBHOOK",
    re.IGNORECASE,
)

_ENV_TOKEN = re.compile(r"\bos\.environ\b|\bos\.getenv\b|\bprocess\.env\b")
_CONST = r"[A-Z][A-Z0-9_]*"
_LIT = r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"

# `process.env.NAME`: the one read whose name is not an argument.
_DOTTED_READ = re.compile(r"\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)")
# A computed name is accepted only in one shape: taken from a table entry,
# `provider["env"]` or `entry.env`. A bare parameter - `os.environ.get(name)`
# - can be anything a tool call asks for, so it ends the question.
_TABLE_ARG = re.compile(r"\s*\w+\s*(?:\[\s*['\"]\w+['\"]\s*\]|\.\w+)\s*[,)\]]")
# Every call-shaped read; its argument decides what kind it is.
_DYNAMIC_READS = [
    re.compile(r"\bos\.environ\.get\s*\("),
    re.compile(r"\bos\.environ\s*\["),
    re.compile(r"\bos\.getenv\s*\("),
    re.compile(r"\bprocess\.env\s*\["),
]
_GETENV_BARE = re.compile(r"(?<![\w.])getenv\s*\(")

_URL = re.compile(r"https?://([A-Za-z0-9._~-]+)")
_ENV_NAME_LITERAL = re.compile(r"['\"]([A-Z][A-Z0-9_]{2,})['\"]")
# A provider-prefixed model name in a table: `"model": "groq/..."` or
# `model="groq/..."`. Only the model slot counts - a bare "openai/gpt-oss"
# in a list of NVIDIA model ids is a name, not a litellm route.
_MODEL_LITERAL = re.compile(
    r"(?:['\"]model['\"]\s*:\s*|\bmodel\s*=\s*)['\"`]([a-z][a-z0-9_]*)/[^'\"`\s]+['\"`]"
)

# `NAME = "literal"` (Python), `const NAME = "literal"` (JS/TS), module level
# or not - a constant is a constant.
_ASSIGN = re.compile(
    r"^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+)?(" + _CONST + r")\s*(?::[^=]*)?=\s*"
    r"[rbuRBU]?['\"`]([^'\"`]*)['\"`]"
)

# Where a call names its destination.
_CLIENT_METHOD = re.compile(
    r"\b\w*(?:client|session|Client|Session|http)\.(?:get|post|put|patch|delete|head|request|send|stream)\s*\("
)
_CONSTRUCTOR = re.compile(
    r"\b(?:httpx2?|aiohttp)\.(?:AsyncClient|Client|ClientSession)\s*\("
)
_LITELLM_CALL = re.compile(r"\blitellm\.\w+\s*\(")


@dataclass(frozen=True)
class ProviderScope:
    """Why a file's credential/network pairing reads as a provider call."""

    pairs: Tuple[Tuple[str, str], ...]   # (credential name, provider label)
    destinations: Tuple[str, ...]        # hosts / litellm providers, sorted

    def describe(self) -> str:
        pairs = ", ".join(f"{name} -> {label}" for name, label in self.pairs)
        return (
            f"every credential it reads is named for a provider it calls ({pairs}), "
            "every call names its destination in the source "
            f"({', '.join(self.destinations)}), and the repository's documentation "
            "names each of them"
        )


def _label(host_or_provider: str) -> str:
    value = host_or_provider.lower()
    if "." in value:
        return _registrable(value)
    return value.split("_")[0]


def _names_match(name: str, label: str) -> bool:
    if len(label) < 3:
        return False
    upper = name.upper()
    return label.upper() in upper.split("_") or upper.startswith(label.upper())


def _constants(scanned: ScannedFile) -> Dict[str, str]:
    """UPPER_CASE names bound to one string literal in this file. A name bound
    to two different literals is left out: it cannot be read off the source."""
    found: Dict[str, str] = {}
    ambiguous: Set[str] = set()
    for line in scanned.lines:
        m = _ASSIGN.match(line)
        if not m:
            continue
        name, value = m.group(1), m.group(2)
        if name in found and found[name] != value:
            ambiguous.add(name)
        found.setdefault(name, value)
    for name in ambiguous:
        del found[name]
    return found


def _split_args(call: str) -> List[str]:
    """Top-level comma-separated arguments of a call's text."""
    args, depth, quote, cur = [], 0, "", []
    for ch in call:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


_HTTP_METHOD = re.compile(r"^['\"](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['\"]$", re.IGNORECASE)


def _url_argument(call: str) -> str:
    """The argument of an HTTP call that names where it goes: `url=`, else
    the first positional one - or the second, when the first is a method
    (`client.stream("GET", url)`, `requests.request("POST", url)`)."""
    args = _split_args(call)
    for arg in args:
        m = re.match(r"^url\s*=\s*(.*)$", arg, re.DOTALL)
        if m:
            return m.group(1)
    positional = [a for a in args if not re.match(r"^\w+\s*=(?!=)", a) and not a.startswith("*")]
    if len(positional) >= 2 and _HTTP_METHOD.match(positional[0]):
        return positional[1]
    return positional[0] if positional else ""


def _call_text(lines: Sequence[str], index: int, start: int, max_lines: int = 15) -> str:
    """Everything inside the call opening at lines[index][start:], up to its
    closing parenthesis (at most `max_lines` lines). Quotes are respected and
    `#` comments dropped."""
    out: List[str] = []
    depth = 0
    quote = ""
    for offset, line in enumerate(lines[index:index + max_lines]):
        text = line[start:] if offset == 0 else line
        for ch in text:
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in "'\"`":
                quote = ch
            elif ch == "#":
                break
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    return "".join(out)
                depth -= 1
            out.append(ch)
        out.append(" ")
    return "".join(out)


def _resolve_url(expr: str, constants: Dict[str, str]) -> Optional[str]:
    """Host named by an argument expression, or None when it is computed."""
    expr = expr.strip()
    m = re.match(r"^[fFrRbBuU]{0,2}['\"`](.*)", expr)
    if m:
        body = m.group(1)
        direct = _URL.match(body)
        if direct:
            return direct.group(1).lower()
        lead = re.match(r"^\$?\{(" + _CONST + r")\}", body)
        if lead:
            return _resolve_url(constants.get(lead.group(1), ""), {}) if lead.group(1) in constants else None
        return None
    lead = re.match(r"^(" + _CONST + r")\b", expr)
    if lead and lead.group(1) in constants:
        value = constants[lead.group(1)]
        direct = _URL.match(value)
        return direct.group(1).lower() if direct else None
    direct = _URL.match(expr)
    return direct.group(1).lower() if direct else None


def _keyword_value(call_text: str, keyword: str) -> Optional[str]:
    m = re.search(r"\b" + keyword + r"\s*=\s*", call_text)
    if not m:
        return None
    rest = call_text[m.end():]
    depth = 0
    out = []
    quote = ""
    for ch in rest:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        out.append(ch)
    return "".join(out).strip()


_TABLE_BASE = re.compile(r"['\"]?(?:api_base|base_url)['\"]?\s*[:=]\s*['\"]https?://([A-Za-z0-9._~-]+)")


def _model_providers(scanned: ScannedFile, code: Set[int]) -> Set[str]:
    """Destinations named by provider-prefixed model literals in this file.

    A table entry can pair an OpenAI-compatible model name with its own
    `api_base` (`{"model": "openai/...", "api_base": "https://x"}`); within
    three lines of each other, the api_base host is the destination, not the
    prefix.
    """
    found = set()
    for index in code:
        for m in _MODEL_LITERAL.finditer(scanned.line_at(index)):
            if m.group(1) not in LITELLM_PROVIDERS:
                continue
            entry = _enclosing_entry(scanned.lines, index - 1, m.start())
            hit = _TABLE_BASE.search(entry)
            found.add(hit.group(1).lower() if hit else m.group(1))
    return found


def _enclosing_entry(lines: Sequence[str], index: int, col: int, reach: int = 8) -> str:
    """The `{...}` literal around lines[index][col], within `reach` lines, or
    just that line when there is none. Brackets inside strings are rare
    enough in a provider table that they are not special-cased."""
    lo = max(0, index - reach)
    before = "\n".join(lines[lo:index] + [lines[index][:col]])
    after = "\n".join([lines[index][col:]] + lines[index + 1:index + 1 + reach])
    depth, start = 0, None
    for pos in range(len(before) - 1, -1, -1):
        ch = before[pos]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                start = pos if ch == "{" else None
                break
            depth -= 1
    if start is None:
        return lines[index]
    depth = 0
    for pos, ch in enumerate(after):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return before[start:] + after[:pos + 1]
            depth -= 1
    return lines[index]


def _resolve_model(expr: Optional[str], constants: Dict[str, str],
                   table: Set[str]) -> Optional[Set[str]]:
    """Providers a litellm `model=` argument can route to, or None."""
    if expr is None:
        return None
    expr = expr.strip()
    lit = re.match(r"^['\"`]([a-z][a-z0-9_]*)/", expr)
    if lit:
        return {lit.group(1)} if lit.group(1) in LITELLM_PROVIDERS else None
    const = re.match(r"^(" + _CONST + r")$", expr)
    if const:
        value = constants.get(const.group(1), "")
        prefix = value.split("/", 1)[0] if "/" in value else ""
        return {prefix} if prefix in LITELLM_PROVIDERS else None
    # A model taken from a table (`provider["model"]`): the destinations are
    # the provider-prefixed model literals in this file, and nothing else.
    return set(table) or None


def litellm_providers(lines: Sequence[str], index: int, start: int,
                      constants: Dict[str, str], table: Set[str]) -> Optional[Set[str]]:
    """Providers the litellm call at lines[index][start:] can reach, or None
    when the call leaves its destination to runtime (a computed api_base, a
    model that is neither a literal nor taken from a table of literals)."""
    call = _call_text(lines, index, start)
    for keyword in ("api_base", "base_url"):
        base = _keyword_value(call, keyword)
        if base is not None and base != "None" and _resolve_url(base, constants) is None:
            return None
    model = _keyword_value(call, "model")
    if model is None and re.search(r"\*\*\s*\w", call):
        # `**primary` - the model comes out of a dict, i.e. out of a table.
        model = "<table>"
    providers = _resolve_model(model, constants, table)
    if providers is None:
        return None
    if _keyword_value(call, "fallbacks") is not None:
        # Fallback models come from the same place a table-driven model does.
        if not table:
            return None
        providers = providers | table
    return providers


def litellm_destination(scanned: ScannedFile, line: int) -> Optional[str]:
    """The provider host(s) of the litellm call on `line`, for a report row."""
    text = scanned.line_at(line)
    m = _LITELLM_CALL.search(text)
    if not m:
        return None
    prose = prose_lines(scanned.path, "\n".join(scanned.lines), scanned.extension)
    code = {i for i in range(1, len(scanned.lines) + 1) if i not in prose}
    providers = litellm_providers(scanned.lines, line - 1, m.end(), _constants(scanned),
                                  _model_providers(scanned, code))
    if not providers:
        return None
    return ", ".join(LITELLM_PROVIDERS.get(p, p) for p in sorted(providers))


def scope(scanned: ScannedFile, docs_text: str) -> Optional[ProviderScope]:
    """A ProviderScope when this file's env reads are provider credentials
    sent only to documented, literal destinations; None otherwise."""
    prose = prose_lines(scanned.path, "\n".join(scanned.lines), scanned.extension)
    code = {i for i in range(1, len(scanned.lines) + 1) if i not in prose}
    constants = _constants(scanned)

    # ---- 1. credentials -------------------------------------------------
    names: Set[str] = set()
    dynamic = False
    for index in sorted(code):
        line = scanned.line_at(index)
        total = len(_ENV_TOKEN.findall(line))
        if _GETENV_BARE.search(line):
            # `getenv(name)` without os. - count it as a read of its own.
            m = re.search(r"(?<![\w.])getenv\s*\(\s*" + _LIT, line)
            if m:
                names.add(m.group(1))
            else:
                return None
        if not total:
            continue
        # Every mention of the environment on this line has to be a read of
        # one variable. Anything left over is the whole environment going
        # somewhere - `dict(os.environ)`, `env=os.environ`, `{...process.env}`.
        call_forms = sum(len(p.findall(line)) for p in _DYNAMIC_READS)
        dotted = _DOTTED_READ.findall(line)
        if call_forms + len(dotted) < total:
            return None
        names.update(dotted)
        for pattern in _DYNAMIC_READS:
            for m in pattern.finditer(line):
                # The argument, even when the call breaks after its `(`.
                arg = line[m.end():]
                if not arg.strip():
                    arg = scanned.line_at(index + 1)
                literal = re.match(r"\s*" + _LIT, arg)
                const = re.match(r"\s*(" + _CONST + r")\s*(?:[,)\]]|$)", arg)
                if literal:
                    names.add(literal.group(1))
                elif const and const.group(1) in constants:
                    names.add(constants[const.group(1)])
                elif _TABLE_ARG.match(arg):
                    dynamic = True
                else:
                    # A parameter, an imported constant, a constant bound
                    # twice: a name this file does not show.
                    return None
    if dynamic:
        table = {m.group(1) for i in code
                 for m in _ENV_NAME_LITERAL.finditer(scanned.line_at(i))
                 if _SECRETISH.search(m.group(1))}
        if not table:
            return None
        names |= table
    secrets = sorted(n for n in names if _SECRETISH.search(n))
    if not secrets:
        return None

    # ---- 2. destinations ------------------------------------------------
    destinations: Set[str] = set()
    for index in code:
        for m in _URL.finditer(scanned.line_at(index)):
            host = m.group(1).lower()
            if host not in _LOOPBACK and host not in _INFRASTRUCTURE:
                destinations.add(host)
    model_table = _model_providers(scanned, code)
    lines = scanned.lines
    for index in sorted(code):
        line = scanned.line_at(index)
        for m in _LITELLM_CALL.finditer(line):
            providers = litellm_providers(lines, index - 1, m.end(), constants, model_table)
            if providers is None:
                return None
            destinations |= providers
        for m in _CONSTRUCTOR.finditer(line):
            call = _call_text(lines, index - 1, m.end())
            base = _keyword_value(call, "base_url")
            if base is not None and _resolve_url(base, constants) is None:
                return None
        for m in _CLIENT_METHOD.finditer(line):
            if _resolve_url(_url_argument(_call_text(lines, index - 1, m.end())), constants) is None:
                return None
        for pattern in (r"\brequests\.(?:get|post|put|patch|delete|request)\s*\(",
                        r"\bhttpx2?\.(?:get|post|put|patch|delete|request|stream)\s*\(",
                        r"(?<![\w.])fetch\s*\(",
                        r"\baxios\.(?:get|post|put|patch|delete|request)\s*\(",
                        r"urlopen\s*\("):
            for m in re.finditer(pattern, line):
                if _resolve_url(_url_argument(_call_text(lines, index - 1, m.end())), constants) is None:
                    return None
        if re.search(r"socket\.socket\s*\(|net\.createConnection|new\s+WebSocket|gethostbyname|dns\.(?:resolve|lookup)", line):
            return None
    if not destinations:
        return None

    # ---- 3 + 4. documented, not suspicious ------------------------------
    docs = docs_text.lower()
    for dest in destinations:
        if dest in _SUSPICIOUS_HOSTS or _IP_LITERAL.match(dest):
            return None
        label = _label(dest)
        domain = ".".join(dest.split(".")[-2:]) if "." in dest else LITELLM_PROVIDERS.get(dest, "")
        if not (re.search(r"\b" + re.escape(label) + r"\b", docs)
                or (domain and domain.lower() in docs)):
            return None

    pairs = []
    for name in secrets:
        label = next((_label(d) for d in sorted(destinations) if _names_match(name, _label(d))), None)
        if label is None:
            return None
        pairs.append((name, label))
    return ProviderScope(pairs=tuple(pairs), destinations=tuple(sorted(destinations)))
