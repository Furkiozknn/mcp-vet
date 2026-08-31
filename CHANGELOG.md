# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
