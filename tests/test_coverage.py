"""Tests for the NIST 800-171r2 coverage computation."""

from __future__ import annotations

from mappers import coverage


def _status(compliance_status: dict, cid: str) -> str:
    return compliance_status["controls"][cid]["status"]


def test_catalog_has_all_110_requirements():
    data = coverage._load_catalog()
    assert data["totalRequirements"] == 110
    assert len(data["requirements"]) == 110


def test_compute_coverage_buckets_requirements():
    # Minimal compliance status with a known mix of statuses.
    compliance = {
        "controls": {
            "AC-1": {"title": "Access Control Policy", "status": "COMPLIANT"},
            "AC-2": {"title": "Account Management", "status": "PARTIAL"},
            "AC-3": {"title": "Access Enforcement", "status": "COMPLIANT"},
            "AC-6": {"title": "Least Privilege", "status": "PARTIAL"},
            "AT-1": {"title": "Training", "status": "PARTIAL"},
        }
    }
    result = coverage.compute_coverage(compliance)
    assert result["totalRequirements"] == 110
    summary = result["summary"]
    assert summary["measured"] + summary["policy_only"] + summary["not_measured"] == 110
    # Every 3.1.x requirement that maps to AC-2/3/6 (technical) should be measured, not policy-only.
    access_family = next(f for f in result["families"] if f["key"] == "3.1")
    r311 = next(r for r in access_family["requirements"] if r["id"] == "3.1.1")
    assert r311["coverageLevel"] == "measured"
    assert any(m["controlId"] == "AC-3" for m in r311["mapping"])
    # Best-of: AC-3 is COMPLIANT, so 3.1.1 effective status is COMPLIANT.
    assert r311["effectiveStatus"] == "COMPLIANT"


def test_policy_only_when_mapping_is_dash_one_only():
    compliance = {"controls": {"AT-1": {"title": "Training", "status": "PARTIAL"}}}
    result = coverage.compute_coverage(compliance)
    training = next(f for f in result["families"] if f["key"] == "3.2")
    # 3.2.1 is mapped to AT-1 only (policy-only control).
    r321 = next(r for r in training["requirements"] if r["id"] == "3.2.1")
    assert r321["coverageLevel"] == "policy_only"
    assert r321["effectiveStatus"] == "PARTIAL"


def test_not_measured_when_empty_mapping():
    compliance = {"controls": {}}
    result = coverage.compute_coverage(compliance)
    boundary_family = next(f for f in result["families"] if f["key"] == "3.13")
    # 3.13.10 (manage crypto keys) has no mapping in the catalog.
    r313_10 = next(r for r in boundary_family["requirements"] if r["id"] == "3.13.10")
    assert r313_10["coverageLevel"] == "not_measured"
    assert r313_10["note"]


def test_family_counts_match_nist():
    result = coverage.compute_coverage({"controls": {}})
    expected = {
        "3.1": 22, "3.2": 3, "3.3": 9, "3.4": 9, "3.5": 11, "3.6": 3,
        "3.7": 6, "3.8": 9, "3.9": 2, "3.10": 6, "3.11": 3, "3.12": 4,
        "3.13": 16, "3.14": 7,
    }
    for family in result["families"]:
        assert len(family["requirements"]) == expected[family["key"]]
