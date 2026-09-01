#!/usr/bin/env python3
"""vet.py — standalone CLI for the mcp-vet star/fork/age heuristic.

Automates SKILL.md Steps 2-4 (search, vet, rank) so the mechanical, fully
deterministic parts of the pipeline can be run directly — from a shell, from
CI, or by Claude Code via Bash — without walking an LLM through hand-composed
`gh api` calls.

This script is deliberately READ-ONLY and SIDE-EFFECT-FREE:

  * It never clones a repository.
  * It never writes to `.mcp.json` or `~/.claude/skills/`.
  * It never installs anything.

It stops exactly where SKILL.md says a human (or Claude, in-loop) has to take
over: Step 5 (read every executable file for red flags) and Step 6 (install
only with explicit approval) are judgment calls this script does not attempt
to automate away. "check" and "search" only print a report — they don't
decide anything on your behalf.

No third-party dependencies: talks to the GitHub REST API directly over
`urllib.request`, so `python3 vet.py ...` works with no `pip install` step.
Set GITHUB_TOKEN (or GH_TOKEN) in the environment to raise the otherwise-low
unauthenticated rate limit; no token is required for occasional use.

Usage:
    python3 vet.py check <owner>/<repo>
    python3 vet.py search "<need> mcp" [--limit N]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

GITHUB_API = "https://api.github.com"
USER_AGENT = "mcp-vet/vet.py"

# The heuristic from SKILL.md Step 3 / README "suspicious-repo heuristic" —
# kept as named constants so the report can cite the exact thresholds it used.
SUSPICIOUS_STAR_THRESHOLD = 3000
SUSPICIOUS_AGE_DAYS = 180
SUSPICIOUS_FORK_RATIO = 0.12

# Secondary signal from SKILL.md Step 3: "no commits in 6+ months" is stale.
STALE_DAYS = 180


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class RepoMeta:
    """The fields SKILL.md Step 3 says to pull via `gh api`."""

    full_name: str
    description: Optional[str]
    html_url: str
    stars: int
    forks: int
    created_at: str  # ISO 8601 UTC, e.g. "2024-01-01T00:00:00Z"
    pushed_at: str
    archived: bool
    license: Optional[str]

    @classmethod
    def from_github_json(cls, data: dict) -> "RepoMeta":
        license_info = data.get("license") or {}
        return cls(
            full_name=data["full_name"],
            description=data.get("description"),
            html_url=data.get("html_url", f"https://github.com/{data['full_name']}"),
            stars=data.get("stargazers_count", 0),
            forks=data.get("forks_count", 0),
            created_at=data["created_at"],
            pushed_at=data["pushed_at"],
            archived=bool(data.get("archived", False)),
            license=license_info.get("name") if license_info else None,
        )


# --------------------------------------------------------------------------
# The heuristic — pure functions, no I/O, fully unit-testable
# --------------------------------------------------------------------------


def parse_iso(timestamp: str) -> datetime:
    """Parse a GitHub API UTC timestamp like '2024-01-01T00:00:00Z'."""
    return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def age_days(created_at: str, now: datetime) -> int:
    return (now - parse_iso(created_at)).days


def fork_ratio(forks: int, stars: int) -> float:
    return forks / stars if stars > 0 else 0.0


def is_suspicious(stars: int, forks: int, created_at: str, now: datetime) -> bool:
    """SKILL.md Step 3 heuristic — flagged only when ALL THREE hold at once."""
    if not (stars > SUSPICIOUS_STAR_THRESHOLD):
        return False
    if not (age_days(created_at, now) < SUSPICIOUS_AGE_DAYS):
        return False
    return fork_ratio(forks, stars) < SUSPICIOUS_FORK_RATIO


def evaluate(meta: RepoMeta, now: Optional[datetime] = None) -> dict:
    """Run the full vetting summary (heuristic + secondary signals) on one repo."""
    now = now or datetime.now(timezone.utc)
    return {
        "suspicious": is_suspicious(meta.stars, meta.forks, meta.created_at, now),
        "age_days": age_days(meta.created_at, now),
        "fork_ratio": fork_ratio(meta.forks, meta.stars),
        "stale": (now - parse_iso(meta.pushed_at)).days > STALE_DAYS,
        "license_missing": meta.license is None,
        "archived": meta.archived,
    }


# --------------------------------------------------------------------------
# GitHub API access (the only I/O in this file)
# --------------------------------------------------------------------------


def _request(url: str) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            raise SystemExit(f"error: not found — {url}")
        if exc.code == 403 and "rate limit" in body.lower():
            raise SystemExit(
                "error: GitHub API rate limit hit. Set GITHUB_TOKEN in your "
                "environment to raise the limit, then retry."
            )
        raise SystemExit(f"error: GitHub API returned {exc.code} for {url}\n{body}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"error: could not reach GitHub API ({exc.reason})")


def fetch_repo(owner_repo: str) -> RepoMeta:
    return RepoMeta.from_github_json(_request(f"{GITHUB_API}/repos/{owner_repo}"))


def search_repos(query: str, limit: int) -> list[RepoMeta]:
    """Mirrors SKILL.md Step 2's `gh search repos "<need> mcp"`."""
    params = urllib.parse.urlencode({"q": query, "sort": "stars", "order": "desc", "per_page": limit})
    data = _request(f"{GITHUB_API}/search/repositories?{params}")
    return [RepoMeta.from_github_json(item) for item in data.get("items", [])]


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def format_check_report(meta: RepoMeta, result: dict) -> str:
    lines = [
        f"Repo:        {meta.full_name}",
        f"Description: {meta.description or '(none)'}",
        f"URL:         {meta.html_url}",
        f"Stars:       {meta.stars}",
        f"Forks:       {meta.forks}  (ratio {result['fork_ratio']:.3f})",
        f"Age:         {result['age_days']} days (created {meta.created_at[:10]})",
        f"Last push:   {meta.pushed_at[:10]}"
        + ("  [STALE: 180+ days since a push]" if result["stale"] else ""),
        f"License:     {meta.license or 'none'}",
        f"Archived:    {'yes' if meta.archived else 'no'}",
        "",
    ]
    if result["suspicious"]:
        lines += [
            "Verdict: SUSPICIOUS",
            (
                f"  stars > {SUSPICIOUS_STAR_THRESHOLD} AND age < {SUSPICIOUS_AGE_DAYS}d "
                f"AND forks/stars < {SUSPICIOUS_FORK_RATIO} all hold."
            ),
            "  This is a disclosed flag, not a verdict — a young official-org repo",
            "  can legitimately grow fast. It means the popularity signal doesn't",
            "  match the usual star/fork/age relationship, so read the source",
            "  before installing (SKILL.md Step 5). Never skip that step.",
        ]
    else:
        lines.append("Verdict: not flagged by the star/fork/age heuristic.")
        lines.append("  (Not flagged is not the same as vetted — still read the source before install.)")

    secondary = []
    if result["stale"]:
        secondary.append("stale (no push in 180+ days)")
    if result["license_missing"]:
        secondary.append("no license on file")
    if result["archived"]:
        secondary.append("archived")
    if secondary:
        lines.append("")
        lines.append("Secondary signals: " + "; ".join(secondary))

    return "\n".join(lines)


def format_search_table(results: list[tuple[RepoMeta, dict]]) -> str:
    if not results:
        return "No candidates found."

    header = f"{'#':<3}{'repo':<40}{'stars':>7}{'forks':>7}{'age(d)':>8}{'ratio':>8}  flag"
    lines = [header, "-" * len(header)]
    for i, (meta, result) in enumerate(results, start=1):
        flag = "SUSPICIOUS" if result["suspicious"] else ""
        lines.append(
            f"{i:<3}{meta.full_name:<40}{meta.stars:>7}{meta.forks:>7}"
            f"{result['age_days']:>8}{result['fork_ratio']:>8.3f}  {flag}"
        )
    lines.append("")
    lines.append(
        "Not flagged does not mean vetted. Per SKILL.md: clone the pick to a"
        " scratch dir and read every executable file before installing anything."
    )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    meta = fetch_repo(args.repo)
    result = evaluate(meta)
    print(format_check_report(meta, result))
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    candidates = search_repos(args.query, args.limit)
    results = [(meta, evaluate(meta)) for meta in candidates]
    print(format_search_table(results))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vet.py",
        description=(
            "Read-only mcp-vet CLI: runs the SKILL.md star/fork/age heuristic "
            "against GitHub without an LLM in the loop. Never clones, installs, "
            "or writes anything — see SKILL.md Steps 5-6 for what still needs a human."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Vet a single repo, e.g. `vet.py check owner/repo`")
    p_check.add_argument("repo", help="owner/repo")
    p_check.set_defaults(func=cmd_check)

    p_search = sub.add_parser("search", help='Search + rank candidates, e.g. `vet.py search "discord mcp"`')
    p_search.add_argument("query", help="search terms, mirroring SKILL.md's `gh search repos` step")
    p_search.add_argument("--limit", type=int, default=5, help="max candidates to show (default: 5)")
    p_search.set_defaults(func=cmd_search)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
