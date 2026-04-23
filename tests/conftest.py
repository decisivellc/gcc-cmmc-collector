"""Shared fixtures for the test suite."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def sample_evidence() -> dict:
    path = Path(__file__).resolve().parent / "sample_data.json"
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    data["collected_at"] = "2099-04-20T14:30:00Z"
    data["tenant_id"] = "00000000-0000-0000-0000-000000000000"
    return data
