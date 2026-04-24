"""Tests for run history archive, listing, diff, and prune."""

from __future__ import annotations

import json
import time
from pathlib import Path

import history


EVIDENCE = {
    "collected_at": "2026-04-24T18:00:00Z",
    "tenant_id": "t-1",
    "collection_warnings": [],
}
COMPLIANCE_STATUS = {
    "summary": {"overallPercentage": 38, "compliant": 34, "partial": 15, "notAddressed": 61},
    "controls": {
        "AC-1": {"title": "Access Control Policy", "status": "PARTIAL"},
        "AC-3": {"title": "Access Enforcement", "status": "COMPLIANT"},
    },
}
REMEDIATION = {"quick_win": [], "medium": [], "heavy_lift": []}
READINESS = {
    "total": 110, "compliant": 34, "partial": 15, "notAddressed": 61, "percentage": 38,
}


def test_archive_run_writes_all_files(tmp_path):
    archive_dir = history.archive_run(
        tmp_path, EVIDENCE, COMPLIANCE_STATUS, REMEDIATION, "<html/>", READINESS
    )
    assert archive_dir.is_dir()
    assert (archive_dir / "evidence.json").exists()
    assert (archive_dir / "compliance-report.html").exists()
    assert (archive_dir / "remediation-backlog.json").exists()
    meta = json.loads((archive_dir / "meta.json").read_text())
    assert meta["readiness"]["percentage"] == 38
    assert meta["readiness"]["total"] == 110


def test_list_runs_newest_first(tmp_path):
    history.archive_run(tmp_path, EVIDENCE, COMPLIANCE_STATUS, REMEDIATION, "<html/>", READINESS)
    time.sleep(1.1)  # timestamps are second-precision
    history.archive_run(tmp_path, EVIDENCE, COMPLIANCE_STATUS, REMEDIATION, "<html/>", READINESS)
    runs = history.list_runs(tmp_path)
    assert len(runs) == 2
    assert runs[0]["timestamp"] > runs[1]["timestamp"]


def test_list_runs_ignores_non_archive_folders(tmp_path):
    (tmp_path / "archive").mkdir()
    (tmp_path / "archive" / "not-a-timestamp").mkdir()
    (tmp_path / "archive" / "notes.txt").write_text("hi")
    assert history.list_runs(tmp_path) == []


def test_load_run_returns_evidence(tmp_path):
    archive_dir = history.archive_run(
        tmp_path, EVIDENCE, COMPLIANCE_STATUS, REMEDIATION, "<html/>", READINESS
    )
    ts = archive_dir.name
    loaded = history.load_run(tmp_path, ts)
    assert loaded is not None
    assert loaded["evidence"]["tenant_id"] == "t-1"
    assert loaded["timestamp"] == ts


def test_load_run_rejects_bogus_timestamp(tmp_path):
    assert history.load_run(tmp_path, "../../etc/passwd") is None
    assert history.load_run(tmp_path, "2026-04-24T181234Z") is None  # doesn't exist


def test_compute_diff_detects_improvement():
    prev = {"controls": {"AC-1": {"title": "AC", "status": "PARTIAL"}}}
    curr = {"controls": {"AC-1": {"title": "AC", "status": "COMPLIANT"}}}
    diff = history.compute_diff(prev, curr)
    assert len(diff["improved"]) == 1
    assert diff["improved"][0]["id"] == "AC-1"
    assert not diff["regressed"]


def test_compute_diff_detects_regression():
    prev = {"controls": {"SC-7": {"title": "Boundary", "status": "COMPLIANT"}}}
    curr = {"controls": {"SC-7": {"title": "Boundary", "status": "PARTIAL"}}}
    diff = history.compute_diff(prev, curr)
    assert len(diff["regressed"]) == 1
    assert diff["hasChanges"] is True


def test_compute_diff_empty_when_no_changes():
    state = {"controls": {"AC-1": {"title": "AC", "status": "COMPLIANT"}}}
    assert history.compute_diff(state, state)["hasChanges"] is False


def test_compute_diff_with_no_previous():
    curr = {"controls": {"AC-1": {"title": "AC", "status": "COMPLIANT"}}}
    diff = history.compute_diff(None, curr)
    assert len(diff["added"]) == 1


def test_prune_keeps_recent(tmp_path):
    # Create one recent archive.
    history.archive_run(tmp_path, EVIDENCE, COMPLIANCE_STATUS, REMEDIATION, "<html/>", READINESS)
    removed = history.prune_runs(tmp_path, keep_days=365)
    assert removed == 0


def test_prune_removes_old(tmp_path):
    # Manually create an ancient-looking folder.
    archive_root = tmp_path / "archive"
    archive_root.mkdir()
    old = archive_root / "2020-01-01T000000Z"
    old.mkdir()
    (old / "meta.json").write_text("{}")
    removed = history.prune_runs(tmp_path, keep_days=30)
    assert removed == 1
    assert not old.exists()
