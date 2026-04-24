"""Persistence and lookup for manual attestations.

An attestation is IT staff's assertion about a requirement that the tool
cannot automatically verify. It records the status they're claiming, a
short rationale, who made the claim, and when — plus an optional review
date so stale attestations surface later.

Attestations only fill in gaps: when an automated signal exists for a
requirement (i.e. it's mapped to an internal control), that takes
precedence. Attestations apply to the unmeasured requirements.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

VALID_STATUSES = ("COMPLIANT", "PARTIAL", "NOT_ADDRESSED")

_LOCK = threading.Lock()


def default_path() -> Path:
    raw = os.environ.get("CMMC_ATTESTATIONS_PATH")
    if raw:
        return Path(raw)
    # Fall back to a path parallel to reports/. In Docker this lands in /app/data/.
    return Path(os.environ.get("CMMC_OUTPUT_DIR", "./reports")).parent / "attestations.json"


def load(path: Path | None = None) -> dict[str, dict[str, Any]]:
    path = path or default_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("attestations file unreadable (%s); ignoring: %s", path, exc)
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict)}


def save(records: dict[str, dict[str, Any]], path: Path | None = None) -> None:
    path = path or default_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with path.open("w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, sort_keys=True)


def upsert(
    requirement_id: str,
    status: str,
    rationale: str,
    attested_by: str,
    review_by: str | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    """Add or replace the attestation for one requirement. Returns the new record."""
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status}")
    records = load(path)
    record = {
        "status": status,
        "rationale": rationale.strip(),
        "attestedBy": attested_by,
        "attestedAt": datetime.now(timezone.utc).isoformat(),
    }
    if review_by:
        record["reviewBy"] = review_by
    records[requirement_id] = record
    save(records, path)
    return record


def remove(requirement_id: str, path: Path | None = None) -> bool:
    records = load(path)
    if requirement_id not in records:
        return False
    del records[requirement_id]
    save(records, path)
    return True
