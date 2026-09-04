"""Shared test helpers. No test in this suite touches the real network."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# A fixed "today" so age-based assertions never drift as the calendar moves.
NOW = datetime(2026, 8, 31, tzinfo=timezone.utc)


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def repo_json(**overrides) -> dict:
    data = {
        "full_name": "acme/widget-mcp",
        "description": "An example MCP server",
        "html_url": "https://github.com/acme/widget-mcp",
        "stargazers_count": 100,
        "forks_count": 30,
        "created_at": iso(1000),
        "pushed_at": iso(1),
        "archived": False,
        "license": {"name": "MIT"},
        "owner": {"type": "Organization", "login": "acme"},
        "open_issues_count": 3,
        "default_branch": "main",
        "topics": ["mcp"],
        "fork": False,
        "disabled": False,
        "size": 120,
    }
    data.update(overrides)
    return data


def mock_response(payload):
    """A stand-in for urlopen's context manager returning JSON bytes."""
    cm = MagicMock()
    cm.__enter__.return_value.read.return_value = json.dumps(payload).encode("utf-8")
    return cm
