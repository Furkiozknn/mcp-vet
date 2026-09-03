"""Minimal HTTP plumbing shared by the GitHub and MCP Registry clients.

The original vet.py raised SystemExit from inside its request helper. That is
fine for a two-command script and wrong for a library: it makes the network
layer untestable except through process exit, and it means any caller wanting
to degrade gracefully - which is the whole point of `--offline` and of
"UNAVAILABLE is not the same as clean" - cannot. So failures are exceptions
here, and only the CLI decides they are fatal.

Still standard library only: `urllib.request`, so `python3` alone runs the tool
with no install step.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

USER_AGENT = "mcp-vet"
DEFAULT_TIMEOUT = 15

# Responses larger than this are refused rather than buffered. A hostile or
# broken endpoint should not be able to exhaust memory through us.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


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


def get_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Any:
    """GET a URL and parse JSON, raising a typed FetchError on any failure."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)

    req = urllib.request.Request(url, headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
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

    if len(raw) > MAX_RESPONSE_BYTES:
        raise FetchError(f"response from {url} exceeded {MAX_RESPONSE_BYTES} bytes", url=url)

    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise FetchError(f"malformed JSON from {url}: {exc}", url=url) from exc


def encode_query(params: Dict[str, Any]) -> str:
    return urllib.parse.urlencode(params)
