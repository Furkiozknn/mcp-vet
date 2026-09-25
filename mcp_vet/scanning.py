"""Reading an untrusted repository without getting hurt by it.

Everything mcp-vet reads is hostile until proven otherwise, and it is read on
behalf of an AI agent that will then print it. That makes this module the
security boundary of the whole tool, so it does three jobs:

1. **Bound the work.** Repositories contain 200MB minified bundles, generated
   lockfiles and vendored dependency trees. Reading those into memory to regex
   over them is how a scanner becomes unusable, and an attacker who knows the
   limits can hide code past them - so skipped files are *reported*, never
   silently dropped.

2. **Never execute anything.** Nothing here imports, compiles, or runs target
   code. Files are bytes, then text, then never anything else. There is no
   code path in mcp-vet that executes what it analyzes.

3. **Neutralize the text before it travels.** Repository content ends up in a
   terminal and in an agent's context window. A description containing ANSI
   escapes can rewrite what the user sees on screen; text containing
   bidirectional-override characters can make a line of source read as the
   opposite of what it compiles to (the "Trojan Source" class of bug). Both are
   defanged here, once, at the boundary - not hopefully, at each print site.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

# Files above this are not read. Real MCP server source is far smaller; what
# lives above the line is bundles, lockfiles and data blobs.
MAX_FILE_BYTES = 512 * 1024

# Stop before walking a whole vendored dependency tree.
MAX_FILES_SCANNED = 3000

# Only the first chunk of a file is pattern-matched. Long files are usually
# long because they are generated.
MAX_LINES_PER_FILE = 6000

# Directories that are somebody else's code, or build output. Skipping these is
# both a performance decision and a correctness one: findings inside
# node_modules are not findings about *this* server.
IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env.d", "dist", "build", "target", ".next", ".nuxt", ".cache",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "vendor",
    "site-packages", ".gradle", ".idea", ".vscode", "coverage", ".nyc_output",
})

# Extensions worth reading as executable source.
SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash",
    ".zsh", ".rb", ".go", ".rs", ".java", ".php", ".ps1", ".pl", ".lua",
})

# Extensions read as configuration or documentation - scanned for different
# things (install hooks, tool descriptions) but scanned nonetheless.
CONFIG_EXTENSIONS = frozenset({
    ".json", ".toml", ".yaml", ".yml", ".cfg", ".ini", ".md", ".txt",
})

# Files worth reading regardless of extension.
NOTABLE_FILENAMES = frozenset({
    "Dockerfile", "Makefile", "makefile", "Procfile", ".npmrc", ".pypirc",
})


@dataclass
class ScannedFile:
    """One file, already read, decoded and made safe to print."""

    path: str            # repo-relative, always forward-slashed
    text: str
    lines: List[str]
    size_bytes: int
    truncated: bool = False

    @property
    def extension(self) -> str:
        return os.path.splitext(self.path)[1].lower()

    def line_at(self, index: int) -> str:
        """1-indexed, bounds-safe."""
        if 1 <= index <= len(self.lines):
            return self.lines[index - 1]
        return ""


@dataclass
class ScanResult:
    files: List[ScannedFile]
    skipped_too_large: List[Tuple[str, int]]
    skipped_binary: List[str]
    hit_file_limit: bool = False

    @property
    def paths(self) -> List[str]:
        return [f.path for f in self.files]


# --------------------------------------------------------------------------
# Making untrusted text safe to display
# --------------------------------------------------------------------------

# CSI/OSC escapes and other C1 control sequences. An OSC 8 hyperlink can make
# "api.github.com" in the report point anywhere, and a CSI sequence can erase
# the lines above it - both turn a security report into a lie.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")

# Bidirectional overrides and invisible formatting characters. These let source
# render in an order different from how it executes.
_BIDI_AND_INVISIBLE = re.compile(
    "[‪-‮⁦-⁩​-‏؜﻿  ]"
)

# Remaining C0 controls, keeping tab and newline which are legitimate.
_C0_CONTROLS = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: Optional[str]) -> str:
    """Strip anything that could manipulate a terminal or misrepresent order.

    Applied to every piece of repository-derived text before it can reach the
    report - snippets, descriptions, repo names, host names. Removing rather
    than escaping is deliberate: an escaped sequence is still a sequence a
    downstream consumer might un-escape.
    """
    if not value:
        return ""
    cleaned = _ANSI_ESCAPE.sub("", value)
    cleaned = _BIDI_AND_INVISIBLE.sub("", cleaned)
    cleaned = _C0_CONTROLS.sub("", cleaned)
    return cleaned


def snippet(text: str, limit: int = 200) -> str:
    """One safe, single-line, bounded excerpt fit for a report."""
    cleaned = sanitize_text(text).replace("\t", " ").strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return cleaned


def looks_binary(chunk: bytes) -> bool:
    """A NUL byte in the first block is the classic, cheap binary test."""
    return b"\x00" in chunk[:8192]


# --------------------------------------------------------------------------
# Walking a tree
# --------------------------------------------------------------------------


def _is_ignored(rel_dir: str) -> bool:
    return any(part in IGNORED_DIRS for part in rel_dir.split("/") if part)


def interesting(path: str) -> bool:
    """Whether a repo-relative path is worth reading at all."""
    name = os.path.basename(path)
    if name in NOTABLE_FILENAMES:
        return True
    ext = os.path.splitext(name)[1].lower()
    return ext in SOURCE_EXTENSIONS or ext in CONFIG_EXTENSIONS


def iter_files(root: str) -> Iterator[str]:
    """Yield repo-relative paths worth reading, skipping ignored subtrees.

    Symlinks are not followed. A symlink into /etc or a self-referential loop
    would otherwise let the repository being audited steer the scanner outside
    its own tree.
    """
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if rel_dir == ".":
            rel_dir = ""
        # Prune in place so os.walk never descends into them at all.
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS)
        if rel_dir and _is_ignored(rel_dir):
            continue
        for name in sorted(filenames):
            rel = f"{rel_dir}/{name}" if rel_dir else name
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            if interesting(rel):
                yield rel


def read_file(root: str, rel_path: str) -> Optional[ScannedFile]:
    """Read one file, or return None if it is too large, binary or unreadable."""
    full = os.path.join(root, rel_path)
    try:
        size = os.path.getsize(full)
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        with open(full, "rb") as handle:
            raw = handle.read(MAX_FILE_BYTES)
    except OSError:
        return None
    if looks_binary(raw):
        return None

    text = raw.decode("utf-8", errors="replace")
    text = sanitize_text(text)
    lines = text.splitlines()
    truncated = False
    if len(lines) > MAX_LINES_PER_FILE:
        lines = lines[:MAX_LINES_PER_FILE]
        text = "\n".join(lines)
        truncated = True
    return ScannedFile(path=rel_path, text=text, lines=lines, size_bytes=size, truncated=truncated)


def scan_tree(root: str, max_files: int = MAX_FILES_SCANNED) -> ScanResult:
    """Read a whole repository under explicit, reported limits.

    Whatever gets skipped is returned rather than discarded, so the report can
    say what it did not look at. A scanner that quietly ignores the one 2MB
    file in the tree is worse than one that admits it.
    """
    files: List[ScannedFile] = []
    too_large: List[Tuple[str, int]] = []
    binary: List[str] = []
    hit_limit = False

    for rel in iter_files(root):
        if len(files) >= max_files:
            hit_limit = True
            break
        full = os.path.join(root, rel)
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            too_large.append((rel, size))
            continue
        scanned = read_file(root, rel)
        if scanned is None:
            binary.append(rel)
            continue
        files.append(scanned)

    return ScanResult(
        files=files,
        skipped_too_large=too_large,
        skipped_binary=binary,
        hit_file_limit=hit_limit,
    )


def source_files(result: ScanResult) -> List[ScannedFile]:
    return [f for f in result.files if f.extension in SOURCE_EXTENSIONS]


def find_files(result: ScanResult, names: Sequence[str]) -> Dict[str, ScannedFile]:
    """Locate specific filenames anywhere in the tree, nearest the root first.

    A manifest at the repository root describes the server; one three
    directories down usually describes an example or a sub-package, so depth is
    the tie-breaker.
    """
    wanted = {n.lower() for n in names}
    found: Dict[str, ScannedFile] = {}
    for scanned in sorted(result.files, key=lambda f: (f.path.count("/"), f.path)):
        base = os.path.basename(scanned.path).lower()
        if base in wanted and base not in found:
            found[base] = scanned
    return found


# --------------------------------------------------------------------------
# What part of the repository does a file belong to?
# --------------------------------------------------------------------------
#
# IGNORED_DIRS already encodes the idea that "a finding inside node_modules is
# not a finding about this server". This extends the same idea one step: a
# finding inside a test fixture, a release script or an issue template is also
# not a finding about what the server does when it runs.
#
# It is not hypothetical. Auditing three widely-installed servers produced a
# HIGH on each, and all three were outside the shipped code:
#
#   github/github-mcp-server    pkg/utils/api_test.go
#   GLips/Figma-Context-MCP     .github/ISSUE_TEMPLATE/bug_report.md
#   microsoft/playwright-mcp    roll.js   (a release script)
#
# A reader told "HIGH: contacts a webhook-capture destination" about a bug
# report template learns nothing and stops trusting the next finding. That is
# exactly the noise this tool exists to be an alternative to.
#
# Crucially this does NOT suppress anything - risk.py's rule is that a finding
# is always reported at its true severity. It only decides what the HEADLINE
# verdict is allowed to rest on.

_TEST_DIR_PARTS = frozenset({
    "test", "tests", "testing", "__tests__", "spec", "specs",
    "fixture", "fixtures", "testdata", "test_data", "e2e", "conftest",
})

_DEV_DIR_PARTS = frozenset({
    ".github", ".gitlab", ".circleci", "scripts", "script", "tools",
    "hack", "ci", "build-tools", "devtools", "examples", "example",
    "samples", "sample", "demo", "demos", "benchmarks", "benchmark",
})

_DOC_EXTENSIONS = frozenset({".md", ".mdx", ".rst", ".txt", ".adoc"})

_TEST_NAME = re.compile(
    r"(^|[._-])(test|tests|spec|conftest|fixtures?)([._-]|$)|(^|/)test_[^/]*$",
    re.IGNORECASE,
)

SHIPPED, TEST, DEV, DOCS = "shipped", "test", "dev", "docs"

# --------------------------------------------------------------------------
# Is this mention a use, or a refusal to use?
# --------------------------------------------------------------------------
#
# The same idea as file_role, one level finer. A server that writes
#
#     SECRET_FILENAMES = {".env", ".netrc", "id_rsa", "credentials.json"}
#
# so that it will never index those files is doing the opposite of reading
# credentials - and until this existed, mcp-vet rated it HIGH for "references
# .netrc credentials" and told the reader DO NOT INSTALL. A tool that punishes
# the defensive pattern harder than its absence teaches people to write the
# unsafe version, which is a worse outcome than saying nothing.
#
# The test is deliberately narrow: the mention must be inside a collection
# literal whose assignment target is named like an exclusion. Anything else -
# a function call, a comparison, an f-string, a variable with an ordinary name -
# is still a plain match. Narrow is the point: a security tool's
# false-negative is the expensive one, so this only fires on a shape that has
# no other plausible reading.
#
# And, as everywhere else here, it SUPPRESSES NOTHING. The finding is still
# reported at full severity, with its file and line. It only stops being
# allowed to set the headline verdict, and the report says why.

_EXCLUSION_NAME = re.compile(
    r"\b[A-Za-z_]*("
    r"deny|denied|denylist|blocklist|blacklist|exclude|excluded|exclusion"
    r"|skip|skipped|ignore|ignored|forbid|forbidden|refuse|never"
    r"|secret_file|sensitive_file|redact|sanitiz|scrub|filter_out"
    r")[A-Za-z_]*\s*(?::[^=]*)?=",
    re.IGNORECASE,
)

_OPENERS = "([{"
_CLOSERS = ")]}"


def _depth_before(lines, index: int, start: int) -> int:
    """Bracket depth accumulated from ``start`` up to (not including) ``index``."""
    depth = 0
    for i in range(start, index):
        line = lines[i]
        # Strings can hold brackets; for this purpose the cheap count is
        # enough, because a mismatch only costs us a missed qualification.
        for ch in line:
            if ch in _OPENERS:
                depth += 1
            elif ch in _CLOSERS:
                depth = max(0, depth - 1)
    return depth


#: How far back to look for the assignment that opened the literal. A denylist
#: longer than this is not one line of shape any more, it is a data file.
EXCLUSION_LOOKBACK = 25


def line_is_exclusion(lines, line_no: int) -> bool:
    """Is line ``line_no`` (1-based) inside a collection literal of exclusions?

    True when the line itself is such an assignment, or when an assignment
    whose name reads as an exclusion opened a bracket that is still open at
    this line.
    """
    if line_no < 1 or line_no > len(lines):
        return False
    here = lines[line_no - 1]
    if _EXCLUSION_NAME.search(here):
        return True
    start = max(0, line_no - 1 - EXCLUSION_LOOKBACK)
    for i in range(line_no - 2, start - 1, -1):
        candidate = lines[i]
        if not _EXCLUSION_NAME.search(candidate):
            continue
        # The assignment has to still be open at our line.
        if _depth_before(lines, line_no - 1, i) > 0:
            return True
        return False
    return False

# --------------------------------------------------------------------------
# Prose: a line that cannot do anything
# --------------------------------------------------------------------------
#
# The other half of the same problem. `local_notes_search.py` explains its own
# denylist in the docstring of the function that applies it:
#
#     Credential-shaped file names (.env, id_rsa, credentials.json, .netrc,
#     *.pem, ...) are never indexed.
#
# A regex over lines cannot tell that apart from code that opens the file. But
# Python can: `tokenize` says exactly which lines are comments or string
# literals, with no heuristics and no guessing. A comment cannot read an SSH
# key, and a docstring that describes a refusal is the strongest possible
# evidence that the refusal exists.
#
# Only Python is done precisely. For other languages a whole-line `#` or `//`
# comment is recognised and nothing else is, because a half-right string
# tokenizer for five languages would introduce exactly the false negatives
# this file is careful to avoid.

_LINE_COMMENT = re.compile(r"^\s*(#|//|--\s|;)")

_prose_cache: dict = {}


def prose_lines(path: str, text: str, extension: str) -> frozenset:
    """1-based line numbers that are comment or string-literal only.

    For .py this is exact: Python's own tokenizer decides. A file that does not
    parse returns an empty set rather than a guess - an unparseable file is
    exactly where a scanner should stay literal.
    """
    key = (path, len(text))
    hit = _prose_cache.get(key)
    if hit is not None:
        return hit

    lines = text.splitlines()
    result = set()
    if extension == ".py":
        import io as _io
        import tokenize as _tok

        try:
            code_lines = set()
            prose_candidates = set()
            for tok in _tok.generate_tokens(_io.StringIO(text).readline):
                if tok.type in (_tok.COMMENT, _tok.STRING):
                    for n in range(tok.start[0], tok.end[0] + 1):
                        prose_candidates.add(n)
                elif tok.type not in (_tok.NL, _tok.NEWLINE, _tok.INDENT,
                                      _tok.DEDENT, _tok.ENDMARKER):
                    code_lines.add(tok.start[0])
            # A line with real code on it is not prose, even if a string
            # also starts there: `open(".netrc")` must never qualify.
            result = prose_candidates - code_lines
        except (SyntaxError, _tok.TokenError, IndentationError, ValueError):
            result = set()
    else:
        for i, line in enumerate(lines, start=1):
            if _LINE_COMMENT.match(line):
                result.add(i)

    frozen = frozenset(result)
    _prose_cache[key] = frozen
    return frozen




def file_role(path: str) -> str:
    """Which part of the repository this path belongs to.

    Returns one of SHIPPED / TEST / DEV / DOCS. Order matters: a markdown file
    under .github is documentation first, and a test helper under scripts/ is
    still a test.

    **Known limit, deliberately not fixed.** A dev script sitting at the
    repository root with an ordinary name - `roll.js`, `release.js` - is
    classified SHIPPED, because nothing in its path distinguishes it from a
    server entry point. Guessing from the filename would risk the opposite
    error: marking real server code as tooling and quietly dropping it out of
    the verdict. In a security tool, over-reporting is the survivable mistake
    and under-reporting is not, so the asymmetry is chosen on purpose.
    """
    p = path.replace("\\", "/").strip("/")
    parts = [seg.lower() for seg in p.split("/")]
    base = parts[-1] if parts else ""
    ext = os.path.splitext(base)[1].lower()

    if ext in _DOC_EXTENSIONS:
        return DOCS
    if any(seg in _TEST_DIR_PARTS for seg in parts[:-1]) or _TEST_NAME.search(base):
        return TEST
    if any(seg in _DEV_DIR_PARTS for seg in parts[:-1]):
        return DEV
    return SHIPPED


def is_shipped(path: Optional[str]) -> bool:
    """True when the path is code that runs as part of the server.

    A finding with no path at all (a manifest-level observation, say) counts as
    shipped: the alternative is silently dropping it from the verdict.
    """
    if not path:
        return True
    return file_role(path) == SHIPPED
