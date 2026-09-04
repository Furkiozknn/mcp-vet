"""GitHub REST client and the repository metadata mcp-vet reasons about.

Read-only by construction: every call here is a GET. Nothing in this module
clones, writes or authenticates beyond an optional bearer token used purely to
raise the rate limit.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .http import FetchError, NotFound, encode_query, get_json, github_token
from .scanning import sanitize_text

GITHUB_API = "https://api.github.com"


def _headers() -> Dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@dataclass
class RepoMeta:
    """Repository facts, with every free-text field already sanitized.

    Descriptions and names come from whoever owns the repository, so they are
    untrusted input that will be printed into a terminal and into an agent's
    context. They are cleaned once, here, on the way in.
    """

    full_name: str
    description: Optional[str]
    html_url: str
    stars: int
    forks: int
    created_at: str
    pushed_at: str
    archived: bool
    license: Optional[str]
    # Trust signals beyond the original six.
    owner_type: Optional[str] = None      # "User" or "Organization"
    owner_login: Optional[str] = None
    open_issues: int = 0
    default_branch: str = "main"
    topics: List[str] = field(default_factory=list)
    homepage: Optional[str] = None
    is_fork: bool = False
    disabled: bool = False
    size_kb: int = 0

    @classmethod
    def from_github_json(cls, data: dict) -> "RepoMeta":
        license_info = data.get("license") or {}
        owner = data.get("owner") or {}
        return cls(
            full_name=sanitize_text(data["full_name"]),
            description=sanitize_text(data.get("description")) or None,
            html_url=data.get("html_url", f"https://github.com/{data['full_name']}"),
            stars=data.get("stargazers_count", 0) or 0,
            forks=data.get("forks_count", 0) or 0,
            created_at=data["created_at"],
            pushed_at=data["pushed_at"],
            archived=bool(data.get("archived", False)),
            license=sanitize_text(license_info.get("name")) or None if license_info else None,
            owner_type=owner.get("type"),
            owner_login=sanitize_text(owner.get("login")) or None,
            open_issues=data.get("open_issues_count", 0) or 0,
            default_branch=data.get("default_branch") or "main",
            topics=[sanitize_text(t) for t in (data.get("topics") or [])],
            homepage=sanitize_text(data.get("homepage")) or None,
            is_fork=bool(data.get("fork", False)),
            disabled=bool(data.get("disabled", False)),
            size_kb=data.get("size", 0) or 0,
        )


@dataclass
class RepoExtras:
    """Optional enrichment. Every field may legitimately be unknown.

    These come from separate API calls that can each fail independently, so
    `None` means "we could not find out", never "zero" - the report has to be
    able to tell those apart.
    """

    contributors: Optional[int] = None
    releases: Optional[int] = None
    latest_release_tag: Optional[str] = None
    latest_release_at: Optional[str] = None
    tags: Optional[List[str]] = None
    errors: List[str] = field(default_factory=list)


def fetch_repo(owner_repo: str) -> RepoMeta:
    return RepoMeta.from_github_json(get_json(f"{GITHUB_API}/repos/{owner_repo}", headers=_headers()))


def search_repos(query: str, limit: int) -> List[RepoMeta]:
    params = encode_query(
        {"q": query, "sort": "stars", "order": "desc", "per_page": max(1, min(limit, 100))}
    )
    data = get_json(f"{GITHUB_API}/search/repositories?{params}", headers=_headers())
    items = data.get("items", []) if isinstance(data, dict) else []
    return [RepoMeta.from_github_json(item) for item in items]


def fetch_extras(owner_repo: str) -> RepoExtras:
    """Best-effort enrichment: each call may fail without failing the audit."""
    extras = RepoExtras()

    # `per_page=1` plus the Link header would be the exact way to count
    # contributors; without header access here we take the first page and
    # report it as a floor rather than pretending to an exact number.
    try:
        contributors = get_json(
            f"{GITHUB_API}/repos/{owner_repo}/contributors?per_page=100&anon=false",
            headers=_headers(),
        )
        if isinstance(contributors, list):
            extras.contributors = len(contributors)
    except FetchError as exc:
        extras.errors.append(f"contributors: {exc.message}")

    try:
        releases = get_json(
            f"{GITHUB_API}/repos/{owner_repo}/releases?per_page=100", headers=_headers()
        )
        if isinstance(releases, list):
            extras.releases = len(releases)
            if releases:
                latest = releases[0]
                extras.latest_release_tag = sanitize_text(latest.get("tag_name")) or None
                extras.latest_release_at = latest.get("published_at")
    except FetchError as exc:
        extras.errors.append(f"releases: {exc.message}")

    try:
        tags = get_json(f"{GITHUB_API}/repos/{owner_repo}/tags?per_page=100", headers=_headers())
        if isinstance(tags, list):
            extras.tags = [sanitize_text(t.get("name", "")) for t in tags if t.get("name")]
    except FetchError as exc:
        extras.errors.append(f"tags: {exc.message}")

    return extras


def fetch_file(owner_repo: str, path: str, ref: Optional[str] = None) -> Optional[str]:
    """Fetch one text file's contents, or None if it does not exist.

    Used for the online path where a repository is inspected without cloning
    it. Returns sanitized text; binary content returns None rather than being
    decoded into nonsense.
    """
    url = f"{GITHUB_API}/repos/{owner_repo}/contents/{path}"
    if ref:
        url += f"?{encode_query({'ref': ref})}"
    try:
        data = get_json(url, headers=_headers())
    except NotFound:
        return None
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return None
    try:
        raw = base64.b64decode(data.get("content", ""))
    except Exception:
        return None
    if b"\x00" in raw[:8192]:
        return None
    return sanitize_text(raw.decode("utf-8", errors="replace"))


def fetch_tree(owner_repo: str, ref: str) -> Optional[List[Dict[str, Any]]]:
    """List every path at a ref in one call, or None if it could not be read."""
    try:
        data = get_json(
            f"{GITHUB_API}/repos/{owner_repo}/git/trees/{ref}?recursive=1",
            headers=_headers(),
        )
    except FetchError:
        return None
    if not isinstance(data, dict):
        return None
    return [entry for entry in data.get("tree", []) if entry.get("type") == "blob"]
