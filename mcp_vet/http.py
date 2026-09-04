"""Minimal HTTP plumbing shared by the GitHub and MCP Registry clients.

The original vet.py raised SystemExit from inside its request helper. That is
fine for a two-command script and wrong for a library: it makes the network
layer untestable except through process exit, and it means any caller wanting
to degrade gracefully - which is the whole point of `--offline` and of
"UNAVAILABLE is not the same as clean" - cannot. So failures are exceptions
here, and only the CLI decides they are fatal.

Still standard library only: `urllib.request`, so `python3` alone runs the tool
with no install step.

Responses are cached on disk, because the network is what an audit actually
waits on. Measured in September 2026: the four GitHub calls of an audit take
about a second between them, while one MCP Registry search the registry has
not cached on its own side takes 5-9 seconds whatever `limit` is asked for,
and a provenance lookup runs three. The cache is an optimisation with an
audit trail, never a source of truth:

* a body is reused without asking the server for `MCP_VET_CACHE_TTL` seconds
  (default one hour), and every report says how many responses that covered
  and how old the oldest was;
* after that a GitHub body is *revalidated* with `If-None-Match`; a 304 costs
  no rate-limit budget (measured: three 304s and one GET spent one point),
  which matters most to the token-less sixty-requests-an-hour user;
* only URLs, ETags and JSON bodies are stored, never request headers, so the
  token never touches disk; files are created 0600 in a 0700 directory;
* errors, 404s and malformed bodies are never cached, and a corrupt entry is
  deleted rather than trusted.

`MCP_VET_CACHE=0` or `--no-cache` turns it off; `MCP_VET_CACHE_DIR` moves it.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

USER_AGENT = "mcp-vet"
DEFAULT_TIMEOUT = 15

# Responses larger than this are refused rather than buffered. A hostile or
# broken endpoint should not be able to exhaust memory through us.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

CACHE_ENV = "MCP_VET_CACHE"
CACHE_DIR_ENV = "MCP_VET_CACHE_DIR"
CACHE_TTL_ENV = "MCP_VET_CACHE_TTL"
DEFAULT_CACHE_TTL = 3600.0
# Entries not refreshed for this long are deleted on the next write. Expired
# entries are kept until then because their ETag still buys a free 304.
CACHE_PRUNE_AFTER = 7 * 86400.0
_CACHE_FORMAT = 1


class FetchError(Exception):
    """A request did not produce usable data. Carries enough to explain why."""

    def __init__(self, message: str, *, status: Optional[int] = None, url: str = ""):
        super().__init__(message)
        self.message = message
        self.status = status
        self.url = url


class NotFound(FetchError):
    """The resource does not exist (404). Often an expected, benign outcome."""


class RateLimited(FetchError):
    """The remote API refused us for quota reasons, not correctness."""


def github_token() -> Optional[str]:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


# --------------------------------------------------------------------------
# Cache bookkeeping
# --------------------------------------------------------------------------

@dataclass
class CacheStats:
    """What the cache did, so a report can say so.

    `requests` counts round trips that reached the network, 304s included.
    `hits` are bodies served with no round trip at all - the only ones that can
    be stale. `revalidated` bodies were confirmed current by the server.
    """

    requests: int = 0
    hits: int = 0
    revalidated: int = 0
    stored: int = 0
    oldest_seconds: float = 0.0

    def since(self, earlier: "CacheStats") -> "CacheStats":
        """Counters accumulated after `earlier` was taken.

        `oldest_seconds` is a running maximum rather than a counter, so it is
        reported whenever an unvalidated body was used in the window - exact
        for the CLI, which runs one command per process.
        """
        hits = self.hits - earlier.hits
        return CacheStats(
            requests=self.requests - earlier.requests,
            hits=hits,
            revalidated=self.revalidated - earlier.revalidated,
            stored=self.stored - earlier.stored,
            oldest_seconds=self.oldest_seconds if hits else 0.0,
        )


_stats = CacheStats()
_stats_lock = threading.Lock()
_cache_override: Optional[bool] = None
_pruned = False
_prune_lock = threading.Lock()


def cache_stats() -> CacheStats:
    with _stats_lock:
        return CacheStats(**_stats.__dict__)


def reset_cache_stats() -> None:
    global _stats
    with _stats_lock:
        _stats = CacheStats()


def _record(*, requests: int = 0, hits: int = 0, revalidated: int = 0,
            stored: int = 0, age: float = 0.0) -> None:
    with _stats_lock:
        _stats.requests += requests
        _stats.hits += hits
        _stats.revalidated += revalidated
        _stats.stored += stored
        if age > _stats.oldest_seconds:
            _stats.oldest_seconds = age


def set_cache_enabled(enabled: Optional[bool]) -> None:
    """Process-wide override, used by `--no-cache`. None defers to the environment."""
    global _cache_override
    _cache_override = enabled


def cache_enabled() -> bool:
    if _cache_override is not None:
        return _cache_override
    return os.environ.get(CACHE_ENV, "1").strip().lower() not in ("0", "off", "false", "no")


def cache_ttl() -> float:
    raw = os.environ.get(CACHE_TTL_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_CACHE_TTL
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_CACHE_TTL


def cache_dir() -> str:
    explicit = os.environ.get(CACHE_DIR_ENV)
    if explicit:
        return explicit
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "mcp-vet")


def age_text(seconds: float) -> str:
    """'under a minute old', '12 minutes old', '1.5 hours old' - for people, not parsers."""
    if seconds < 60:
        return "under a minute old"
    if seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} old"
    return f"{seconds / 3600:.1f} hours old"


def _cache_path(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return os.path.join(cache_dir(), digest + ".json")


def _cache_read(url: str) -> Optional[Dict[str, Any]]:
    """The stored entry for `url`, or None. Anything malformed is deleted, not trusted."""
    path = _cache_path(url)
    try:
        with open(path, "rb") as handle:
            entry = json.loads(handle.read(MAX_RESPONSE_BYTES * 2))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        entry = None
    if (
        isinstance(entry, dict)
        and entry.get("format") == _CACHE_FORMAT
        and entry.get("url") == url
        and isinstance(entry.get("fetched_at"), (int, float))
        and "body" in entry
    ):
        return entry
    try:
        os.unlink(path)
    except OSError:
        pass
    return None


def _cache_write(url: str, body: Any, etag: Optional[str]) -> None:
    """Store atomically and privately. Failure to cache is never an error."""
    directory = cache_dir()
    try:
        if not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        _prune_once(directory)
        payload = json.dumps(
            {"format": _CACHE_FORMAT, "url": url, "fetched_at": time.time(),
             "etag": etag, "body": body},
            ensure_ascii=False,
        ).encode("utf-8")
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=directory)
    except (OSError, TypeError, ValueError):
        return
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.chmod(tmp, 0o600)
        os.replace(tmp, _cache_path(url))
        _record(stored=1)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _prune_once(directory: str) -> None:
    """Drop entries nobody has touched in a week. Once per process; only our files."""
    global _pruned
    with _prune_lock:
        if _pruned:
            return
        _pruned = True
    cutoff = time.time() - CACHE_PRUNE_AFTER
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        ours = (len(name) == 69 and name.endswith(".json")) or name.startswith(".tmp-")
        if not ours:
            continue
        path = os.path.join(directory, name)
        try:
            if os.stat(path).st_mtime < cutoff:
                os.unlink(path)
        except OSError:
            pass


# --------------------------------------------------------------------------
# The one GET
# --------------------------------------------------------------------------

def _header(resp: Any, name: str) -> Optional[str]:
    """A response header as a string, or None - also when a test's mock has none."""
    headers = getattr(resp, "headers", None)
    getter = getattr(headers, "get", None)
    value = getter(name) if callable(getter) else None
    return value if isinstance(value, str) and value else None


def _http_get(url: str, headers: Dict[str, str], timeout: int) -> Tuple[int, bytes, Optional[str]]:
    """One GET. Returns (status, body, etag); a 304 comes back as (304, b"", None)."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            etag = _header(resp, "ETag")
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return 304, b"", None
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - body is best-effort context only
            pass
        if exc.code == 404:
            raise NotFound(f"not found: {url}", status=404, url=url) from exc
        # GitHub answers 403 for both rate limiting and permissions, and 429
        # once secondary limits kick in; only the body distinguishes them.
        if exc.code in (403, 429) and ("rate limit" in body.lower() or exc.code == 429):
            raise RateLimited(
                "GitHub API rate limit reached. Set GITHUB_TOKEN (or GH_TOKEN) "
                "in your environment to raise it, then retry.",
                status=exc.code,
                url=url,
            ) from exc
        raise FetchError(f"HTTP {exc.code} for {url}", status=exc.code, url=url) from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"could not reach {url} ({exc.reason})", url=url) from exc
    except (TimeoutError, OSError) as exc:
        raise FetchError(f"could not reach {url} ({exc})", url=url) from exc
    return 200, raw, etag


def get_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
    cache: bool = True,
) -> Any:
    """GET a URL and parse JSON, raising a typed FetchError on any failure.

    With the cache on, a body younger than the TTL is returned without a
    request; an older one that carries an ETag is revalidated and reused on
    304; anything else is fetched and, if it parsed, stored.
    """
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    use_cache = cache and cache_enabled()
    entry = _cache_read(url) if use_cache else None
    age = 0.0
    if entry is not None:
        age = max(0.0, time.time() - float(entry["fetched_at"]))
        if age <= cache_ttl():
            _record(hits=1, age=age)
            return entry["body"]
        if isinstance(entry.get("etag"), str) and entry["etag"]:
            request_headers["If-None-Match"] = entry["etag"]

    # Counted before the attempt: a timed-out round trip is still a round
    # trip, and "5 of 5 from cache" would be a lie if two requests failed.
    _record(requests=1)
    status, raw, etag = _http_get(url, request_headers, timeout)

    if status == 304:
        if entry is None:
            # We never asked; a server that answers 304 anyway is broken, and
            # we have nothing to return for it.
            raise FetchError(f"unexpected 304 from {url}", status=304, url=url)
        _cache_write(url, entry["body"], entry.get("etag"))
        _record(revalidated=1)
        return entry["body"]

    if len(raw) > MAX_RESPONSE_BYTES:
        raise FetchError(f"response from {url} exceeded {MAX_RESPONSE_BYTES} bytes", url=url)

    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise FetchError(f"malformed JSON from {url}: {exc}", url=url) from exc

    if use_cache:
        _cache_write(url, body, etag)
    return body


def encode_query(params: Dict[str, Any]) -> str:
    return urllib.parse.urlencode(params)
