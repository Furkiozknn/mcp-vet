# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] — 2026-09-01

### Changed

- **`vet.py` moved to `scripts/vet.py`** (Agent Skills spec convention for
  bundled scripts) and **`test_vet.py` moved to `tests/test_vet.py`** -
  0.2.0 shipped `vet.py` at repo root and SKILL.md referenced it as
  `python3 vet.py ...`, but the README's own Install instructions only ever
  copied `SKILL.md` into `~/.claude/skills/mcp-vet/` - the script itself was
  never actually deployed alongside the skill, so following SKILL.md's own
  Step 3 pointer inside a real Claude Code session would have failed with
  "file not found". Fixed by bundling the script under `scripts/` and
  updating the Install section to copy both.
- SKILL.md Steps 2 and 3 now point to `scripts/vet.py search`/`check` as the
  *preferred* path (one command instead of hand-composing `gh api` calls),
  with the manual `gh api`/`gh search` fallback kept as a documented
  fallback rather than the primary instruction.
- `pyproject.toml`: `testpaths` now `["tests"]` (was `["."]`), added
  `pythonpath = ["scripts"]` so `import vet` in the tests keeps working
  from its new location. `.github/workflows/ci.yml` needed no changes.
- Re-synced the deployed copy at `~/.claude/skills/mcp-vet/` - it had
  drifted behind this repo's SKILL.md (missing the 0.2.0 vet.py pointer
  entirely, despite CHANGELOG 0.2.0 claiming it was added) in addition to
  now also getting `scripts/vet.py`.
- SKILL.md's `scripts/vet.py` calls now run via `uv run python scripts/
  vet.py ...`, not bare `python3 scripts/vet.py ...` - verified live that
  this machine has no working system `python3`/`python` on PATH (only the
  Microsoft Store app-execution-alias stub, which prints "Python was not
  found" and exits), so the bare-`python3` instruction this fix started
  with would itself have failed the moment Claude actually ran it. `uv run
  python` works with zero setup since `uv` manages its own interpreter.
  `compatibility` frontmatter updated to reflect `uv` as the primary
  runtime dependency, `gh` CLI as the documented fallback (was reversed).
  README's own usage examples keep bare `python3` as the general-audience
  default (this is a real interpreter on most machines) with a note about
  the `uv run python` alternative for the same PATH situation.

## [0.2.0] — 2026-08-31

### Added

- `vet.py` — a standalone, zero-dependency CLI that runs the SKILL.md
  star/fork/age heuristic directly against the GitHub REST API:
  - `vet.py check <owner>/<repo>` — vet one repo, print stars/forks/age/
    license/archived status and the suspicious-flag verdict.
  - `vet.py search "<query>"` — search + rank candidates with the same
    per-repo vetting summary, mirroring SKILL.md's Step 2 search phrasing.
  - Read-only and side-effect-free by construction: no clone, no install,
    no writes to `.mcp.json` or `~/.claude/skills/`. It automates Steps
    2-4 of the pipeline (search / vet / rank) only — Step 5 (source review)
    and Step 6 (install) stay human-in-the-loop / Claude-in-the-loop, as
    SKILL.md requires.
- `test_vet.py` — pytest suite covering the heuristic in isolation
  (clearly suspicious, clearly fine, each of the 3 conditions failing
  individually, all three at once, and the exact boundary values),
  `evaluate()`'s secondary signals, and the GitHub API calls mocked out
  (no real network access, no `gh` CLI needed to run CI).
- `.github/workflows/ci.yml` — runs the test suite on push and PR across
  Python 3.9/3.11/3.12.
- `pyproject.toml` — minimal project metadata plus `pytest` as a dev
  dependency, so `pip install -e .[dev]` reproduces the CI environment.
- README: documented the new script (usage, the read-only guarantee, how
  it relates to the skill) alongside the existing pipeline/heuristic docs.
- SKILL.md: one short pointer under Step 3 noting `vet.py` can run that
  step directly instead of hand-composing `gh api` calls. The 7-step
  pipeline itself is unchanged.

## [0.1.0] — initial release

- `SKILL.md` — the seven-step MCP discovery/vetting/install pipeline as a
  Claude Code skill. No app, no dependencies, one Markdown file.
