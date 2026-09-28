"""The scanner's own source must not carry the characters it hunts for.

Bidirectional overrides and zero-width characters let source render in a
different order from how it executes (CVE-2021-42574, "Trojan Source").
mcp-vet detects them in other people's code, so its own detector and
fixtures spell them as \\uXXXX escapes: a reviewer reading a diff sees the
code point, and no editor or terminal can reorder the line around it.
"""
import pathlib

import pytest

from mcp_vet.scanning import sanitize_text

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The same set _BIDI_AND_INVISIBLE removes, plus the soft hyphen and the
# word joiner, which are just as invisible.
FORBIDDEN = (
    set(range(0x202A, 0x202F))
    | set(range(0x2066, 0x206A))
    | set(range(0x200B, 0x2010))
    | {0x061C, 0xFEFF, 0x2028, 0x2029, 0x00AD, 0x2060}
)


def _python_files():
    files = sorted(
        p for p in ROOT.rglob("*.py")
        if not any(part.startswith(".") or part in {"build", "dist"} for part in p.relative_to(ROOT).parts)
    )
    assert files, "no Python files found: the hygiene check would pass on nothing"
    return files


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_raw_bidi_or_invisible_characters(path):
    text = path.read_text(encoding="utf-8")
    hits = [
        f"line {n}: U+{ord(ch):04X}"
        for n, line in enumerate(text.splitlines(), 1)
        for ch in line
        if ord(ch) in FORBIDDEN
    ]
    assert not hits, f"{path.relative_to(ROOT)}: write these as \\uXXXX escapes: {hits}"


@pytest.mark.parametrize("cp", sorted(FORBIDDEN - {0x00AD, 0x2060}))
def test_detector_still_strips_every_escaped_code_point(cp):
    # Escaping the pattern must not have changed what it matches.
    assert chr(cp) not in sanitize_text(f"a{chr(cp)}b")
