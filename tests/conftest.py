"""pytest fixtures. Helper functions live in tests/helpers.py."""
from __future__ import annotations

import pytest

from helpers import NOW


@pytest.fixture
def now():
    """A fixed 'today', so age-based assertions do not drift with the calendar."""
    return NOW
