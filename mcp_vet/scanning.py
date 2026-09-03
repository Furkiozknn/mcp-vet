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
