"""The official MCP Registry, treated as one signal rather than an approval.

Being listed means someone published an entry. It does not mean anyone
reviewed the code, and mcp-vet never treats registry presence as trust. What
the registry is genuinely good for is **provenance**: it states which
repository and which package a server claims to come from, and that claim can
be checked against what is actually on GitHub.

The interesting outcomes are the mismatches:

* the registry points at a different repository than the one you found
* the registry entry declares no repository at all
* the registry version and the repository's latest release disagree

Schema note: this is written against the live v0 API (server schema
2025-12-11), where each result is `{server: {...}, _meta: {...}}` and the
server object carries optional `repository`, `packages` and `remotes`. Sampling
the live registry showed `repository` present on well under half of entries and
`remotes` on most - so *missing provenance is the common case*, not an
anomaly, and it is reported as a limitation rather than an accusation.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .http import FetchError, encode_query, get_json
from .models import (
    Area,
    AreaAssessment,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Status,
)
from .scanning import sanitize_text

REGISTRY_API = "https://registry.modelcontextprotocol.io"
# A search the registry has not cached itself took 5-9 s at a quiet hour and
# 20-50 s under load (measured September 2026); the shared 15 s default turned
# a slow-but-answering registry into a silent "not found". Provenance is worth
# waiting for, the terms are in flight together, and the answer is cached.
REGISTRY_TIMEOUT = 60
OFFICIAL_META_KEY = "io.modelcontextprotocol.registry/official"


@dataclass
class RegistryPackage:
    registry_type: Optional[str] = None
    identifier: Optional[str] = None
    version: Optional[str] = None
    transport: Optional[str] = None
    environment_variables: List[str] = field(default_factory=list)


@dataclass
class RegistryServer:
    name: str
    description: str = ""
    version: Optional[str] = None
    repository_url: Optional[str] = None
    repository_source: Optional[str] = None
    website: Optional[str] = None
    packages: List[RegistryPackage] = field(default_factory=list)
    remotes: List[Tuple[str, str]] = field(default_factory=list)  # (transport, url)
    status: Optional[str] = None
    published_at: Optional[str] = None
    updated_at: Optional[str] = None
    is_latest: Optional[bool] = None

    @property
    def transports(self) -> List[str]:
        found = [p.transport for p in self.packages if p.transport]
        found += [t for t, _ in self.remotes]
        return sorted(set(t for t in found if t))

    @property
    def is_remote_only(self) -> bool:
        return bool(self.remotes) and not self.packages


def _parse_server(entry: Dict[str, Any]) -> RegistryServer:
    server = entry.get("server", entry) or {}
    meta = (entry.get("_meta") or {}).get(OFFICIAL_META_KEY) or {}
    repository = server.get("repository") or {}

    packages: List[RegistryPackage] = []
    for raw in server.get("packages") or []:
        if not isinstance(raw, dict):
            continue
        transport = raw.get("transport") or {}
        env_names = [
            sanitize_text(str(v.get("name", "")))
            for v in (raw.get("environmentVariables") or [])
            if isinstance(v, dict) and v.get("name")
        ]
        packages.append(
            RegistryPackage(
                registry_type=sanitize_text(raw.get("registryType")) or None,
                identifier=sanitize_text(raw.get("identifier")) or None,
                version=sanitize_text(raw.get("version")) or None,
                transport=sanitize_text(transport.get("type")) if isinstance(transport, dict) else None,
                environment_variables=env_names,
            )
        )

    remotes: List[Tuple[str, str]] = []
    for raw in server.get("remotes") or []:
        if isinstance(raw, dict) and raw.get("url"):
            remotes.append(
                (sanitize_text(raw.get("type")) or "unknown", sanitize_text(raw.get("url")))
            )

    return RegistryServer(
        name=sanitize_text(server.get("name", "")),
        description=sanitize_text(server.get("description", "")),
        version=sanitize_text(server.get("version")) or None,
        repository_url=sanitize_text(repository.get("url")) or None,
        repository_source=sanitize_text(repository.get("source")) or None,
        website=sanitize_text(server.get("websiteUrl")) or None,
        packages=packages,
        remotes=remotes,
        status=sanitize_text(meta.get("status")) or None,
        published_at=meta.get("publishedAt"),
        updated_at=meta.get("updatedAt"),
        is_latest=meta.get("isLatest"),
    )


def _dedupe_latest(servers: List[RegistryServer]) -> List[RegistryServer]:
    """One row per server name.

    The API returns every published version as its own entry, so an unfiltered
    listing shows the same server three or four times. Prefer the entry the
    registry marks isLatest; otherwise keep the first seen.
    """
    best: Dict[str, RegistryServer] = {}
    for server in servers:
        current = best.get(server.name)
        if current is None or (server.is_latest and not current.is_latest):
            best[server.name] = server
    return list(best.values())


def search(query: str, limit: int = 20) -> List[RegistryServer]:
    """Search the registry by name.

    The v0 API's `search` parameter is a substring match on the server *name*
    only - confirmed against its published OpenAPI description - so a query
    like "control discord" finds nothing while "discord" finds plenty. Each
    whitespace-separated term is therefore tried on its own and the results
    merged, which turns a natural-language need into something the endpoint can
    actually answer. Descriptions are matched locally afterwards to rank.
    """
    terms = [t for t in re.split(r"\s+", query.strip().lower()) if len(t) > 2] or [query.strip()]
    collected: List[RegistryServer] = []
    seen_names = set()

    pages = _search_pages(terms[:4], min(100, max(limit * 3, 30)))
    failures = [err for _, err in pages if err is not None]
    if failures and len(failures) == len(pages):
        raise failures[0]
    for data, _ in pages:
        if data is None:
            continue
        for entry in data.get("servers") or []:
            if not isinstance(entry, dict):
                continue
            server = _parse_server(entry)
            key = (server.name, server.version)
            if key in seen_names:
                continue
            seen_names.add(key)
            collected.append(server)

    servers = _dedupe_latest(collected)
    lowered_terms = [t for t in terms]
    servers.sort(
        key=lambda s: (
            -sum(1 for t in lowered_terms if t in f"{s.name} {s.description}".lower()),
            s.name,
        )
    )
    return servers[:limit]


def find_by_repository(repo_url: str, candidates_per_term: int = 100) -> Optional[RegistryServer]:
    """Look for a registry entry that declares this repository as its source.

    The API indexes by name, not by repository, so an exhaustive answer would
    mean walking thousands of entries on every audit. Instead the repository's
    owner and name are used as search terms - a server published from
    `acme/discord-mcp` is overwhelmingly likely to be *named* after one of the
    two - and the declared repository URL of each candidate is compared
    properly.

    A miss therefore means "no entry found by this search", never "not in the
    registry", and the caller reports it that way.
    """
    normalized = _normalize_repo(repo_url)
    if not normalized:
        return None
    _, owner, name = normalized.split("/", 2)

    pages = _search_pages(_search_terms(owner, name), min(100, candidates_per_term))
    for data, _ in pages:
        if data is None:
            continue
        for entry in data.get("servers") or []:
            if not isinstance(entry, dict):
                continue
            server = _parse_server(entry)
            if server.repository_url and _normalize_repo(server.repository_url) == normalized:
                return server
    failures = [err for _, err in pages if err is not None]
    if failures:
        # "Could not search" must never read as "searched and found nothing":
        # UNAVAILABLE is not the same as clean. The caller marks provenance
        # unavailable rather than absent.
        first = failures[0]
        raise FetchError(
            f"registry search failed for {len(failures)} of {len(pages)} terms: {first.message}",
            status=first.status, url=first.url,
        )
    return None


def _search_pages(terms: List[str], limit: int) -> List[Tuple[Optional[Dict[str, Any]], Optional[FetchError]]]:
    """One registry search per term, in flight together, results in term order.

    Measured September 2026 with fresh terms, twice: at a quiet hour three
    sequential searches took 11.8 s of wall time and three concurrent ones
    3.4 s; under load, 130 s sequential against 24 s concurrent, with the
    per-query latency *lower* in the concurrent run - the registry's cost is
    per query and it serves queries in parallel without contention. They
    go out together - at most four threads, one per term - and come back in
    term order, so which entry wins a lookup does not depend on which request
    finished first and the report stays byte-stable. Each element is
    (page, None) or (None, error): a term that failed is reported, never
    quietly treated as "no entry". GitHub calls are deliberately not treated
    this way: GitHub asks for serial requests.
    """

    def fetch(term: str) -> Tuple[Optional[Dict[str, Any]], Optional[FetchError]]:
        params = encode_query({"search": term, "limit": limit})
        try:
            data = get_json(f"{REGISTRY_API}/v0/servers?{params}", timeout=REGISTRY_TIMEOUT)
        except FetchError as exc:
            return None, exc
        return (data if isinstance(data, dict) else None), None

    if len(terms) <= 1:
        return [fetch(term) for term in terms]
    with ThreadPoolExecutor(max_workers=len(terms), thread_name_prefix="mcp-vet-registry") as pool:
        return list(pool.map(fetch, terms))


def _search_terms(owner: str, name: str) -> List[str]:
    """Search terms most likely to surface a server published from owner/name."""
    terms = [name, owner]
    # "discord-mcp" and "mcp-discord" both really mean "discord"; the suffix
    # is near-universal in this ecosystem and matches almost everything.
    stripped = re.sub(r"(?:^mcp[-_])|(?:[-_]mcp$)|(?:[-_]?server$)", "", name).strip("-_")
    if stripped and stripped not in terms:
        terms.insert(0, stripped)
    return [t for t in terms if len(t) > 2][:3]


def _normalize_repo(url: Optional[str]) -> Optional[str]:
    """Reduce a repository URL to 'host/owner/name' for comparison."""
    if not url:
        return None
    text = url.strip().rstrip("/")
    text = re.sub(r"^git\+", "", text)
    text = re.sub(r"\.git$", "", text)
    match = re.search(r"(?:https?://|git@)([^/:]+)[/:]([^/]+)/([^/]+)$", text)
    if not match:
        return None
    return f"{match.group(1).lower()}/{match.group(2).lower()}/{match.group(3).lower()}"


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


def assess_provenance(
    server: Optional[RegistryServer],
    github_repo: Optional[str],
    lookup_failed: bool = False,
) -> Tuple[AreaAssessment, List[Finding]]:
    """Compare what the registry claims against the repository being audited."""
    findings: List[Finding] = []

    if lookup_failed:
        return (
            AreaAssessment(
                Area.PROVENANCE,
                Severity.NOT_FLAGGED,
                Status.UNAVAILABLE,
                "The MCP Registry could not be reached, so provenance was not checked. "
                "This is not evidence either way.",
            ),
            findings,
        )

    if server is None:
        return (
            AreaAssessment(
                Area.PROVENANCE,
                Severity.NOT_FLAGGED,
                Status.NOT_APPLICABLE,
                "No matching entry found in the scanned window of the MCP Registry. "
                "Most servers are not registered; absence is not a finding.",
            ),
            findings,
        )

    expected = _normalize_repo(f"https://github.com/{github_repo}") if github_repo else None
    declared = _normalize_repo(server.repository_url)

    if declared and expected and declared != expected:
        findings.append(
            Finding(
                rule_id="provenance.registry_source_mismatch",
                area=Area.PROVENANCE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title="Registry/source mismatch",
                explanation=(
                    f"The registry entry '{server.name}' declares its source as "
                    f"{server.repository_url}, but the repository under audit is "
                    f"{github_repo}. Either this is not the server the registry entry "
                    "describes, or the entry points somewhere unexpected. Installing on "
                    "the strength of the registry listing would in that case install "
                    "something other than what was reviewed."
                ),
                evidence=[Evidence(detail=f"registry: {server.repository_url}"),
                          Evidence(detail=f"audited: https://github.com/{github_repo}")],
                remediation="Establish which of the two is the server you actually want before installing.",
            )
        )
        severity = Severity.HIGH
        summary = f"Registry entry '{server.name}' points at a different repository."
    elif not server.repository_url:
        findings.append(
            Finding(
                rule_id="provenance.no_declared_source",
                area=Area.PROVENANCE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Registry entry declares no source repository",
                explanation=(
                    f"'{server.name}' is published without a repository link, so the "
                    "published artifact cannot be traced back to reviewable source. "
                    "Common in the registry today, and it still means there is nothing "
                    "to read before trusting it."
                ),
                evidence=[Evidence(detail=f"registry entry: {server.name}")],
                remediation="Prefer a server whose registry entry links to source you can read.",
            )
        )
        severity = Severity.MEDIUM
        summary = f"Registry entry '{server.name}' has no source repository."
    else:
        severity = Severity.NOT_FLAGGED
        summary = (
            f"Registry entry '{server.name}' declares {server.repository_url}, "
            "which matches the repository audited. Listing is a provenance link, "
            "not a review."
        )

    if server.status and server.status.lower() != "active":
        findings.append(
            Finding(
                rule_id="provenance.registry_status",
                area=Area.PROVENANCE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title=f"Registry marks this server '{server.status}'",
                explanation=(
                    "The registry no longer lists this entry as active, which usually "
                    "means deleted, deprecated or superseded."
                ),
                evidence=[Evidence(detail=f"status={server.status}")],
            )
        )
        severity = max(severity, Severity.MEDIUM, key=lambda s: s.rank)

    if server.is_remote_only:
        findings.append(
            Finding(
                rule_id="provenance.remote_only_server",
                area=Area.PROVENANCE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title="Server is remote-only: you run none of this code",
                explanation=(
                    "This entry declares only remote endpoints ("
                    + ", ".join(url for _, url in server.remotes[:3])
                    + "). Source review tells you what the published code does, but the "
                    "operator can change what that endpoint serves at any time, without "
                    "any repository changing. Everything you send it - including whatever "
                    "the model puts in tool arguments - reaches a third party."
                ),
                evidence=[Evidence(detail=f"{t}: {u}") for t, u in server.remotes[:4]],
                remediation=(
                    "Judge this as a service you are sending data to, not as code you are "
                    "installing: who operates it, under what terms, and what happens to "
                    "the data. Static analysis cannot answer any of those."
                ),
            )
        )
        severity = max(severity, Severity.MEDIUM, key=lambda s: s.rank)

    return AreaAssessment(Area.PROVENANCE, severity, Status.VERIFIED, summary), findings
