"""pytest fixtures. Helper functions live in tests/helpers.py."""
from __future__ import annotations

import pytest

from mcp_vet import http as http_mod

from helpers import NOW


@pytest.fixture
def now():
    """A fixed 'today', so age-based assertions do not drift with the calendar."""
    return NOW


@pytest.fixture(autouse=True)
def _cache_off_and_sandboxed(monkeypatch, tmp_path):
    """No test reads or writes ~/.cache, and the cache is off unless a test opts in.

    Off by default because most tests count mocked requests, and a cache hit
    would silently turn a second call into none.
    """
    monkeypatch.setenv(http_mod.CACHE_ENV, "0")
    monkeypatch.setenv(http_mod.CACHE_DIR_ENV, str(tmp_path / "mcp-vet-cache"))
    monkeypatch.delenv(http_mod.CACHE_TTL_ENV, raising=False)
    monkeypatch.setattr(http_mod, "_pruned", False)
    http_mod.set_cache_enabled(None)
    http_mod.reset_cache_stats()
    yield
    http_mod.set_cache_enabled(None)
