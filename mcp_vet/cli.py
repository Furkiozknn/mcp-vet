"""The mcp-vet command line.

Commands exist only where they answer a different question:

* `search`   - which servers exist for a need (GitHub)
* `registry` - which servers exist for a need (official MCP Registry)
* `check`    - the fast metadata-only look at one repository
* `audit`    - the full analysis, and the one that reads source
* `report`   - `audit`, JSON by default, for another program to consume

Exit codes are part of the interface and are documented in the README, so
`mcp-vet audit owner/repo` can be a CI gate:

    0  nothing above INFO
    1  LOW or MEDIUM findings
    2  HIGH findings
    3  CRITICAL findings
    4  mcp-vet itself could not complete

The distinction between 0 and 4 is the important one: "found nothing" and
"could not look" must never share an exit code, or a broken gate reads as a
passing one.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import diff as diff_mod
from . import registry as registry_mod
from . import risk as risk_mod
from .audit import audit_directory, audit_repository
from .github import fetch_repo, search_repos
from . import http as http_mod
from .http import FetchError, NotFound, RateLimited
from .popularity import assess as popularity_assess
from .popularity import age_days, fork_ratio, is_suspicious
from .models import Severity
from .report import render_search_table, render_text
from .scanning import sanitize_text


def _evaluate_for_table(meta) -> dict:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return {
        "suspicious": is_suspicious(meta.stars, meta.forks, meta.created_at, now),
        "age_days": age_days(meta.created_at, now),
        "fork_ratio": fork_ratio(meta.forks, meta.stars),
    }


def cmd_search(args: argparse.Namespace) -> int:
    candidates = search_repos(args.query, args.limit)
    rows = [(meta, _evaluate_for_table(meta)) for meta in candidates]
    print(render_search_table(rows))
    return risk_mod.EXIT_CLEAN


def cmd_registry(args: argparse.Namespace) -> int:
    servers = registry_mod.search(args.query, limit=args.limit)
    if not servers:
        print("No matching servers in the MCP Registry.")
        print(
            "Note: the registry's search matches server names only, so a phrase may "
            "find nothing where a single keyword finds plenty."
        )
        return risk_mod.EXIT_CLEAN

    print(f"{'server':<44}{'version':<10}source")
    print("-" * 92)
    for server in servers:
        name = server.name if len(server.name) <= 43 else server.name[:40] + "..."
        source = server.repository_url or "(no repository declared)"
        print(f"{name:<44}{(server.version or '?'):<10}{source}")
    print()
    remote_only = [s for s in servers if s.is_remote_only]
    if remote_only:
        print(
            f"{len(remote_only)} of these are remote-only: you would send data to a "
            "service rather than run code you can read."
        )
    print(
        "Registry listing is a provenance link, not a review. Nothing here has been "
        "vetted by anyone; run `mcp-vet audit` on the source before installing."
    )
    return risk_mod.EXIT_CLEAN


def cmd_check(args: argparse.Namespace) -> int:
    """Metadata only - deliberately the weakest command, and it says so."""
    meta = fetch_repo(args.repo)
    assessment, findings = popularity_assess(meta)
    ratio = fork_ratio(meta.forks, meta.stars)
    from datetime import datetime, timezone

    days = age_days(meta.created_at, datetime.now(timezone.utc))

    print(f"Repository   {meta.full_name}")
    print(f"Description  {meta.description or '(none)'}")
    print(f"URL          {meta.html_url}")
    print(f"Owner        {meta.owner_login or '?'} ({meta.owner_type or 'unknown type'})")
    print(f"Stars        {meta.stars}")
    print(f"Forks        {meta.forks}  (ratio {ratio:.3f})")
    print(f"Age          {days} days (created {meta.created_at[:10]})")
    print(f"Last push    {meta.pushed_at[:10]}")
    print(f"License      {meta.license or 'none'}")
    print(f"Archived     {'yes' if meta.archived else 'no'}")
    print(f"Fork         {'yes' if meta.is_fork else 'no'}")
    print()
    print(f"Popularity integrity: {assessment.severity.value}")
    print(f"  {assessment.summary}")
    print()
    print(
        "This is metadata only. It says nothing about what the code does - no source "
        "was read. Run `mcp-vet audit " + args.repo + " --path <checkout>` for that."
    )
    return risk_mod.exit_code_for(assessment.severity)


def cmd_audit(args: argparse.Namespace) -> int:
    if args.offline:
        if not args.path:
            print("error: --offline requires --path <directory>", file=sys.stderr)
            return risk_mod.EXIT_ERROR
        report = audit_directory(args.path, purpose=args.purpose or "", target=args.repo or args.path)
    else:
        if not args.repo:
            print("error: audit needs <owner>/<repo>, or --offline --path <directory>",
                  file=sys.stderr)
            return risk_mod.EXIT_ERROR
        report = audit_repository(
            args.repo,
            local_path=args.path,
            check_registry=not args.no_registry,
        )

    if args.json:
        print(report.to_json())
    else:
        print(render_text(report, verbose=args.verbose, quiet=args.quiet))
    return risk_mod.exit_code_for(report.overall)


def cmd_report(args: argparse.Namespace) -> int:
    args.json = not args.text
    args.verbose = False
    args.quiet = False
    return cmd_audit(args)


class _Subparsers:
    """add_parser() wrapper that keeps allow_abbrev=False on every subcommand.

    argparse does not propagate it, so each subparser has to opt out again.
    """

    def __init__(self, parser: argparse.ArgumentParser):
        self._sub = parser.add_subparsers(dest="command", required=True)

    def add_parser(self, name: str, **kwargs) -> argparse.ArgumentParser:
        kwargs.setdefault("allow_abbrev", False)
        return self._sub.add_parser(name, **kwargs)


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two versions and report capability the newer one gained."""
    if args.before_path or args.after_path:
        if not (args.before_path and args.after_path):
            print("error: --before-path and --after-path must be given together",
                  file=sys.stderr)
            return risk_mod.EXIT_ERROR
        # Label each side by its directory name, which is what a reader
        # recognises, rather than inventing "before"/"after".
        import os

        result = diff_mod.diff_local(
            args.before_path, args.after_path,
            before_ref=args.before or os.path.basename(os.path.abspath(args.before_path)),
            after_ref=args.after or os.path.basename(os.path.abspath(args.after_path)),
        )
    else:
        if not (args.repo and args.before and args.after):
            print("error: diff needs <owner>/<repo> <before-ref> <after-ref>, "
                  "or --before-path and --after-path", file=sys.stderr)
            return risk_mod.EXIT_ERROR
        result = diff_mod.diff_refs(args.repo, args.before, args.after)

    print(diff_mod.render(result))
    # An upgrade that adds capability exits non-zero so it can gate an
    # automated bump, using the worst finding's severity.
    if not result.findings:
        return risk_mod.EXIT_CLEAN
    worst = max(f.severity for f in result.findings)
    return risk_mod.exit_code_for(worst)


def _network_flags() -> argparse.ArgumentParser:
    """Flags shared by every command that talks to GitHub or the registry."""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--no-cache", action="store_true",
        help="ignore the local response cache and ask GitHub and the registry directly",
    )
    return parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-vet",
        # Prefix matching is off deliberately: with it on, `--before` silently
        # resolves to `--before-path`, and a mistyped flag in a security tool
        # should fail loudly rather than mean something else.
        allow_abbrev=False,
        description=(
            "Evidence-gathering for MCP servers. Collects what a server can do, what "
            "credentials it wants, where it can send data, and what its provenance is - "
            "then shows you, with the file and line for every claim. It never decides "
            "that something is safe, and it never installs anything."
        ),
        epilog=(
            "Exit codes: 0 nothing above INFO, 1 low/medium, 2 high, 3 critical, "
            "4 mcp-vet could not complete."
        ),
    )
    sub = _Subparsers(parser)
    net = _network_flags()

    p_search = sub.add_parser("search", parents=[net], help="Find candidate servers on GitHub")
    p_search.add_argument("query", help='e.g. "discord mcp"')
    p_search.add_argument("--limit", type=int, default=10)
    p_search.set_defaults(func=cmd_search)

    p_registry = sub.add_parser("registry", parents=[net], help="Search the official MCP Registry")
    p_registry.add_argument("query", help='e.g. "discord"')
    p_registry.add_argument("--limit", type=int, default=10)
    p_registry.set_defaults(func=cmd_registry)

    p_check = sub.add_parser("check", parents=[net], help="Metadata-only look at one repository")
    p_check.add_argument("repo", help="owner/repo")
    p_check.set_defaults(func=cmd_check)

    p_audit = sub.add_parser("audit", parents=[net], help="Full analysis of one server")
    p_audit.add_argument("repo", nargs="?", help="owner/repo")
    p_audit.add_argument("--path", help="local checkout to analyze (source analysis needs this)")
    p_audit.add_argument("--offline", action="store_true",
                         help="analyze --path only; make no network requests")
    p_audit.add_argument("--no-registry", action="store_true", help="skip the MCP Registry lookup")
    p_audit.add_argument("--purpose", help="what the server claims to do (improves endpoint classification)")
    p_audit.add_argument("--json", action="store_true", help="machine-readable output")
    p_audit.add_argument("--verbose", action="store_true", help="include snippets and area summaries")
    p_audit.add_argument("--quiet", action="store_true", help="verdict line only")
    p_audit.set_defaults(func=cmd_audit)

    p_diff = sub.add_parser(
        "diff",
        parents=[net],
        help="Compare two versions: what capability did the newer one gain?",
    )
    p_diff.add_argument("repo", nargs="?", help="owner/repo")
    p_diff.add_argument("before", nargs="?", help="earlier ref, e.g. v1.2.0")
    p_diff.add_argument("after", nargs="?", help="later ref, e.g. v1.3.0")
    p_diff.add_argument("--before-path", help="local checkout of the earlier version")
    p_diff.add_argument("--after-path", help="local checkout of the later version")
    p_diff.set_defaults(func=cmd_diff)

    p_report = sub.add_parser("report", parents=[net], help="Audit, emitting JSON by default")
    p_report.add_argument("repo", nargs="?", help="owner/repo")
    p_report.add_argument("--path")
    p_report.add_argument("--offline", action="store_true")
    p_report.add_argument("--no-registry", action="store_true")
    p_report.add_argument("--purpose")
    p_report.add_argument("--text", action="store_true", help="render text instead of JSON")
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "no_cache", False):
        http_mod.set_cache_enabled(False)
    network_before = http_mod.cache_stats()
    try:
        code = args.func(args)
    except NotFound as exc:
        print(f"error: not found - {sanitize_text(exc.message)}", file=sys.stderr)
        return risk_mod.EXIT_ERROR
    except RateLimited as exc:
        print(f"error: {sanitize_text(exc.message)}", file=sys.stderr)
        return risk_mod.EXIT_ERROR
    except FetchError as exc:
        print(f"error: {sanitize_text(exc.message)}", file=sys.stderr)
        return risk_mod.EXIT_ERROR
    except KeyboardInterrupt:
        return risk_mod.EXIT_ERROR
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return risk_mod.EXIT_ERROR
    finally:
        # The override must not outlive one invocation: main() is re-entrant
        # for tests and for anyone embedding the CLI.
        http_mod.set_cache_enabled(None)

    # audit and report carry this inside the report, where a JSON consumer can
    # read it; the human-facing commands get one line after their output.
    if args.command in ("search", "registry", "check", "diff"):
        stats = http_mod.cache_stats().since(network_before)
        if stats.hits:
            print(
                f"Note: {stats.hits} response(s) came from the local cache (the oldest is "
                f"{http_mod.age_text(stats.oldest_seconds)}). Use --no-cache for live answers."
            )
    return code


if __name__ == "__main__":
    sys.exit(main())
