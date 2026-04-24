"""Tests for manual attestation persistence and coverage merge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import attestations as attestations_store
from mappers import coverage


def test_load_missing_file_returns_empty(tmp_path):
    assert attestations_store.load(tmp_path / "missing.json") == {}


def test_upsert_writes_record_with_timestamp(tmp_path):
    path = tmp_path / "attest.json"
    record = attestations_store.upsert(
        "3.1.3", "COMPLIANT",
        "Purview sensitivity labels on all CUI sites.",
        attested_by="ops@tenant.us",
        review_by="2027-04-24",
        path=path,
    )
    assert record["status"] == "COMPLIANT"
    assert record["attestedBy"] == "ops@tenant.us"
    assert record["reviewBy"] == "2027-04-24"
    assert "attestedAt" in record
    loaded = json.loads(path.read_text())
    assert loaded["3.1.3"]["rationale"] == "Purview sensitivity labels on all CUI sites."


def test_upsert_rejects_invalid_status(tmp_path):
    with pytest.raises(ValueError):
        attestations_store.upsert(
            "3.1.3", "MAYBE", "no", attested_by="x", path=tmp_path / "a.json"
        )


def test_remove_returns_false_when_absent(tmp_path):
    assert attestations_store.remove("3.1.3", tmp_path / "a.json") is False


def test_remove_deletes_existing(tmp_path):
    path = tmp_path / "a.json"
    attestations_store.upsert("3.1.3", "COMPLIANT", "rationale here", "x", path=path)
    assert attestations_store.remove("3.1.3", path) is True
    assert attestations_store.load(path) == {}


def test_coverage_merges_attestations_for_unmeasured():
    attestations = {
        "3.1.3": {
            "status": "COMPLIANT",
            "rationale": "Purview labels enforced.",
            "attestedBy": "ops@x.us",
            "attestedAt": "2026-04-24T18:00:00Z",
        }
    }
    result = coverage.compute_coverage({"controls": {}}, attestations)
    family = next(f for f in result["families"] if f["key"] == "3.1")
    req = next(r for r in family["requirements"] if r["id"] == "3.1.3")
    assert req["effectiveStatus"] == "COMPLIANT"
    assert req["effectiveStatusSource"] == "attestation"
    assert result["attestedCount"] == 1


def test_coverage_automated_beats_attestation():
    # AC-3 is mapped to 3.1.1 and marked COMPLIANT by the automated mapper.
    compliance = {"controls": {"AC-3": {"title": "Access Enforcement", "status": "COMPLIANT"}}}
    attestations = {
        "3.1.1": {
            "status": "PARTIAL",
            "rationale": "partial attestation",
            "attestedBy": "ops@x.us",
            "attestedAt": "2026-04-24T18:00:00Z",
        }
    }
    result = coverage.compute_coverage(compliance, attestations)
    family = next(f for f in result["families"] if f["key"] == "3.1")
    req = next(r for r in family["requirements"] if r["id"] == "3.1.1")
    assert req["effectiveStatus"] == "COMPLIANT"
    assert req["effectiveStatusSource"] == "automated"
