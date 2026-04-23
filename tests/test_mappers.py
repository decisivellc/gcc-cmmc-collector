"""Tests for the NIST 800-171 mapper."""

from __future__ import annotations

import copy

import pytest

from mappers import nist_800_171
from mappers.nist_800_171 import (
    CONTROL_IDS,
    STATUS_COMPLIANT,
    STATUS_NOT_ADDRESSED,
    STATUS_PARTIAL,
)


def test_all_control_ids_are_mapped(sample_evidence):
    result = nist_800_171.map(sample_evidence)
    assert set(result["controls"].keys()) == set(CONTROL_IDS)
    for control in result["controls"].values():
        assert control["status"] in {STATUS_COMPLIANT, STATUS_PARTIAL, STATUS_NOT_ADDRESSED}
        assert "title" in control
        assert "remediation" in control


def test_summary_counts_add_up(sample_evidence):
    result = nist_800_171.map(sample_evidence)
    summary = result["summary"]
    assert summary["compliant"] + summary["partial"] + summary["notAddressed"] == len(CONTROL_IDS)
    assert 0 <= summary["overallPercentage"] <= 100


def test_ac2_flags_inactive_and_missing_mfa(sample_evidence):
    result = nist_800_171.map(sample_evidence)
    ac2 = result["controls"]["AC-2"]
    assert ac2["status"] == STATUS_PARTIAL
    assert any("inactive" in gap.lower() for gap in ac2["gaps"])
    assert any("mfa" in gap.lower() for gap in ac2["gaps"])


def test_ac2_compliant_when_all_users_active_and_mfa(sample_evidence):
    evidence = copy.deepcopy(sample_evidence)
    for user in evidence["azure_ad"]["users"]:
        if user.get("accountEnabled"):
            user["mfaStatus"] = "enabled"
            user["lastActiveInDays"] = 1
    result = nist_800_171.map(evidence)
    assert result["controls"]["AC-2"]["status"] == STATUS_COMPLIANT


def test_ia2_compliant_when_all_mfa_registered(sample_evidence):
    evidence = copy.deepcopy(sample_evidence)
    for user in evidence["azure_ad"]["users"]:
        if user.get("accountEnabled"):
            user["mfaStatus"] = "enabled"
    result = nist_800_171.map(evidence)
    assert result["controls"]["IA-2"]["status"] == STATUS_COMPLIANT


def test_si2_partial_when_noncompliant_device(sample_evidence):
    result = nist_800_171.map(sample_evidence)
    si2 = result["controls"]["SI-2"]
    assert si2["status"] == STATUS_PARTIAL
    assert any("13.6" in gap or "14.3" in gap or "non-compliant" in gap.lower() for gap in si2["gaps"])


def test_ir1_and_at1_not_addressed_without_policy_docs(sample_evidence):
    evidence = {k: v for k, v in sample_evidence.items() if k != "policies"}
    result = nist_800_171.map(evidence)
    assert result["controls"]["IR-1"]["status"] == STATUS_NOT_ADDRESSED
    assert result["controls"]["AT-1"]["status"] == STATUS_NOT_ADDRESSED


def test_remediation_backlog_buckets_non_compliant_items(sample_evidence):
    result = nist_800_171.map(sample_evidence)
    backlog = nist_800_171.generate_remediation_backlog(result)
    assert set(backlog.keys()) >= {"quick_win", "medium", "heavy_lift"}
    total_tasks = sum(len(tasks) for tasks in backlog.values())
    non_compliant = sum(
        1 for c in result["controls"].values() if c["status"] != STATUS_COMPLIANT
    )
    assert total_tasks == non_compliant


def test_missing_evidence_does_not_crash():
    # Simulate a run where every collector failed.
    evidence = {
        "azure_ad": {"available": False, "error": "x"},
        "intune": {"available": False, "error": "x"},
        "defender": {"available": False, "error": "x"},
        "exchange": {"available": False, "error": "x"},
    }
    result = nist_800_171.map(evidence)
    # All controls should still be present and non-crashing.
    assert set(result["controls"].keys()) == set(CONTROL_IDS)
