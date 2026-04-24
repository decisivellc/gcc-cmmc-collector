"""Persist each run as a timestamped archive, list runs, compute diffs.

Layout:

    reports/
        compliance-report.html    <- latest, always overwritten
        evidence.json             <- latest
        remediation-backlog.json  <- latest
        archive/
            2026-04-24T181234Z/
                evidence.json
                compliance-report.html
                remediation-backlog.json
                meta.json         <- summary for fast listing

``meta.json`` carries the handful of numbers needed to render the
history list without re-parsing the full evidence file.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ARCHIVE_DIRNAME = "archive"
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{6}Z$")


def archive_run(
    output_dir: Path,
    evidence: dict[str, Any],
    compliance_status: dict[str, Any],
    remediation: dict[str, Any],
    html: str,
    readiness: dict[str, Any] | None = None,
) -> Path:
    """Copy the latest run outputs into a timestamped archive folder."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    archive_dir = output_dir / ARCHIVE_DIRNAME / ts
    archive_dir.mkdir(parents=True, exist_ok=True)

    (archive_dir / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (archive_dir / "remediation-backlog.json").write_text(
        json.dumps(remediation, indent=2), encoding="utf-8"
    )
    (archive_dir / "compliance-report.html").write_text(html, encoding="utf-8")

    meta = {
        "timestamp": ts,
        "collectedAt": evidence.get("collected_at"),
        "summary": compliance_status.get("summary", {}),
        "readiness": {
            "total": (readiness or {}).get("total"),
            "compliant": (readiness or {}).get("compliant"),
            "partial": (readiness or {}).get("partial"),
            "notAddressed": (readiness or {}).get("notAddressed"),
            "percentage": (readiness or {}).get("percentage"),
        },
        "collectionWarnings": len(evidence.get("collection_warnings") or []),
    }
    (archive_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return archive_dir


def list_runs(output_dir: Path) -> list[dict[str, Any]]:
    """Return metadata for each archived run, most recent first."""
    archive_root = output_dir / ARCHIVE_DIRNAME
    if not archive_root.exists():
        return []
    runs: list[dict[str, Any]] = []
    for child in archive_root.iterdir():
        if not child.is_dir() or not TIMESTAMP_PATTERN.match(child.name):
            continue
        meta_path = child / "meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        meta["path"] = str(child)
        runs.append(meta)
    runs.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return runs


def load_run(output_dir: Path, timestamp: str) -> dict[str, Any] | None:
    """Load evidence + compliance for a specific archive, or None."""
    if not TIMESTAMP_PATTERN.match(timestamp):
        return None
    archive_dir = output_dir / ARCHIVE_DIRNAME / timestamp
    if not archive_dir.is_dir():
        return None
    evidence_path = archive_dir / "evidence.json"
    if not evidence_path.exists():
        return None
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    meta_path = archive_dir / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    return {"timestamp": timestamp, "evidence": evidence, "meta": meta}


def prune_runs(output_dir: Path, keep_days: int = 365) -> int:
    """Remove archive folders older than ``keep_days``. Returns count removed."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    archive_root = output_dir / ARCHIVE_DIRNAME
    if not archive_root.exists():
        return 0
    removed = 0
    for child in archive_root.iterdir():
        if not child.is_dir() or not TIMESTAMP_PATTERN.match(child.name):
            continue
        try:
            ts = datetime.strptime(child.name, "%Y-%m-%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if ts < cutoff:
            try:
                shutil.rmtree(child)
                removed += 1
            except OSError as exc:
                logger.warning("failed to prune %s: %s", child, exc)
    return removed


def compute_diff(
    previous_status: dict[str, Any] | None,
    current_status: dict[str, Any],
) -> dict[str, Any]:
    """Summarize what changed between two compliance_status snapshots."""
    prev_controls = ((previous_status or {}).get("controls") or {})
    curr_controls = (current_status.get("controls") or {})

    improved: list[dict[str, Any]] = []
    regressed: list[dict[str, Any]] = []
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []

    order = {"COMPLIANT": 0, "PARTIAL": 1, "NOT_ADDRESSED": 2}
    for cid, control in curr_controls.items():
        curr_status = control.get("status")
        prev = prev_controls.get(cid)
        if not prev:
            added.append({"id": cid, "title": control.get("title"), "status": curr_status})
            continue
        prev_status = prev.get("status")
        if prev_status == curr_status:
            continue
        delta = {
            "id": cid,
            "title": control.get("title"),
            "from": prev_status,
            "to": curr_status,
        }
        if order.get(curr_status, 3) < order.get(prev_status, 3):
            improved.append(delta)
        else:
            regressed.append(delta)
    for cid, control in prev_controls.items():
        if cid not in curr_controls:
            removed.append({"id": cid, "title": control.get("title")})

    return {
        "improved": improved,
        "regressed": regressed,
        "added": added,
        "removed": removed,
        "hasChanges": bool(improved or regressed or added or removed),
    }
