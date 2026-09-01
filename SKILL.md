---
name: mcp-vet
description: Discover, vet, and safely install MCP servers for a described need. Searches GitHub, flags likely-inflated or fake repos using a star/fork/age heuristic, reviews the source before anything gets installed. Use when the user asks "is there an MCP for X", "find me an MCP server that does Y", "kur mcp", "hangi MCP var", "bana bir MCP bul", or wants to add a new MCP server safely.
license: MIT
compatibility: Requires the gh CLI (authenticated) and network access to github.com
---

# MCP Vet — discover, vet, and safely install MCP servers

You are helping the user find and safely install a Model Context Protocol (MCP) server that meets a described need. Unlike a plain "find me a package" search, this skill exists specifically to catch two failure modes: installing a repo whose popularity is faked, and installing a repo whose code does something unsafe. Follow the workflow in order — do not skip the vetting or review steps even if a candidate looks obviously good.

## Step 1 — Clarify the need

Restate the need in one line before searching (e.g. "an MCP server that lets Claude control Discord" not just "discord"). If the request is vague, ask one clarifying question rather than guessing scope.

## Step 2 — Search GitHub

Use `gh search repos "<need> mcp"` (and `"<need> mcp server"` as a second phrasing — results vary). If results are thin (under 3 real candidates), also check the major curated lists for a match:
- `punkpeye/awesome-mcp-servers`
- `appcypher/awesome-mcp-servers`
- `wong2/awesome-mcp-servers`

Pull at least 5-10 raw candidates before filtering — a thin initial search misses legitimate but less-SEO'd repos.

## Step 3 — Vet each candidate (the legitimacy heuristic)

For every candidate, pull with `gh api repos/<owner>/<repo> --jq '{stars: .stargazers_count, forks: .forks_count, created: .created_at, pushed: .pushed_at, archived: .archived, license: .license.name}'`.

**Flag as SUSPICIOUS (likely inflated/fake) when ALL three are true:**
- `stargazers_count > 3000`
- Repo age < 180 days (from `created_at` to today)
- `forks_count / stargazers_count < 0.12`

A repo can fail this check and still be real (young official-org projects sometimes grow fast) — but disclose the flag explicitly rather than silently filtering it out or silently recommending it.

This step is mechanical enough to run outside the conversation: `python3 vet.py check <owner>/<repo>` or `python3 vet.py search "<need> mcp"` (shipped in this repo) apply the exact same heuristic and print the same verdict, if hand-composing `gh api` calls isn't necessary. It's read-only and stops there — it never clones or installs anything, so Steps 5 and 6 below still happen here, by you.

**Secondary maturity signals** (no hard cutoff, weigh together):
- `pushed_at` recent (maintained) vs. stale (no commits in 6+ months)
- Non-empty README with real usage docs, not just a marketing blurb
- License present (unlicensed code is a legal yellow flag for reuse, not a safety one)
- Archived repos are deprioritized regardless of star count

## Step 4 — Rank and present top 2-3 candidates

For each: name, stars, forks, age, one-line description, suspicious flag (if any), one-sentence recommendation. Never present only one option unless the search genuinely returned only one real candidate — say so explicitly if that's the case.

## Step 5 — Review before install (never install blind)

For the candidate the user picks (or the top-ranked one if they say "you choose"):

1. Clone to the scratch directory — never straight into `.mcp.json` or `~/.claude/skills/` before this step.
2. List the file tree.
3. Read every executable file (Python/JS/shell/etc — not just the README). Flag explicitly if you see:
   - Network calls to hosts unrelated to the tool's stated purpose
   - Code that reads env vars, credentials, or SSH keys and sends them anywhere
   - Obfuscated or minified source with no matching readable original
   - Install-time scripts (`postinstall`, `setup.py` with arbitrary exec) that do more than the README describes
4. Summarize findings in plain language — "clean, does what it says" or the specific concern found. If something looks wrong, say so and stop; do not install anyway "just to see."

## Step 6 — Install only with explicit approval

- MCP server → add an entry to the workspace-root `.mcp.json` (never `claude_desktop_config.json` — see the `new-mcp-server` skill if this project's environment needs that reminder).
- Skill → copy into `~/.claude/skills/<name>/` (personal, cross-project) or `.claude/skills/` (this project only) depending on what the user wants.
- Delete the scratch clone afterward — matches this workspace's standing hygiene practice: don't leave review clones lying around once the decision is made either way.

## Step 7 — Record it

If the found tool is a recurring category (e.g. "MCP servers for video editing" gets asked more than once), note the shortlist in memory so it isn't re-discovered from scratch next time — but always re-verify star/fork counts live, since they change and a memory snapshot can go stale.

## What this skill deliberately does not do

- Does not auto-install anything without the user seeing the vetting summary first.
- Does not treat a high star count alone as sufficient — the whole point is that star count can be gamed.
- Does not recommend paid/credentialed integrations without flagging the cost or credential requirement up front.
