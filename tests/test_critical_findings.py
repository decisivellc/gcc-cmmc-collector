"""Tests for compound-risk analysis."""

from __future__ import annotations

import critical_findings


def _user(upn, **overrides):
    base = {
        "userPrincipalName": upn,
        "displayName": upn.split("@")[0],
        "accountEnabled": True,
        "mfaStatus": "enabled",
        "assignedRoles": [],
        "signInActivity": {
            "lastSignInDateTime": "2026-04-20T00:00:00Z",
            "lastNonInteractiveSignInDateTime": "2026-04-20T00:00:00Z",
        },
        "lastActiveInDays": 1,
    }
    base.update(overrides)
    return base


def test_clean_user_produces_no_finding():
    evidence = {"azure_ad": {"users": [_user("alice@x.us")]}}
    assert critical_findings.build_critical_findings(evidence) == []


def test_single_factor_does_not_trigger():
    evidence = {
        "azure_ad": {
            "users": [_user("alice@x.us", mfaStatus="disabled")],
        }
    }
    assert critical_findings.build_critical_findings(evidence) == []


def test_two_factors_triggers_finding():
    evidence = {
        "azure_ad": {
            "users": [
                _user(
                    "alice@x.us",
                    mfaStatus="disabled",
                    assignedRoles=["Global Administrator"],
                )
            ],
        }
    }
    findings = critical_findings.build_critical_findings(evidence)
    assert len(findings) == 1
    f = findings[0]
    assert "no_mfa" in f["factors"]
    assert "standing_admin" in f["factors"]
    assert "CRITICAL" in f["recommendation"]


def test_pim_activator_is_not_standing_admin():
    evidence = {
        "azure_ad": {
            "users": [
                _user(
                    "jay@x.us",
                    mfaStatus="disabled",
                    assignedRoles=["Global Administrator"],
                )
            ],
            "auditLogs": {
                "sample": [
                    {
                        "activityDisplayName": "Add member to role completed (PIM activation)",
                        "initiatedBy": "jay@x.us",
                    }
                ]
            },
        }
    }
    findings = critical_findings.build_critical_findings(evidence)
    assert len(findings) == 1
    # Still two factors (no_mfa + privileged), but NOT standing_admin.
    assert "standing_admin" not in findings[0]["factors"]
    assert "privileged" in findings[0]["factors"]


def test_break_glass_excluded():
    evidence = {
        "azure_ad": {
            "users": [
                _user(
                    "BG_RM@x.us",
                    mfaStatus="disabled",
                    assignedRoles=["Global Administrator"],
                    signInActivity={"lastSignInDateTime": None, "lastNonInteractiveSignInDateTime": None},
                )
            ],
        },
        "exceptions": {"break_glass_upns": ["BG_RM@x.us"]},
    }
    assert critical_findings.build_critical_findings(evidence) == []


def test_disabled_account_excluded():
    evidence = {
        "azure_ad": {
            "users": [
                _user(
                    "oldhire@x.us",
                    accountEnabled=False,
                    mfaStatus="disabled",
                    assignedRoles=["Global Administrator"],
                    lastActiveInDays=500,
                )
            ],
        },
    }
    assert critical_findings.build_critical_findings(evidence) == []


def test_findings_sorted_by_severity_descending():
    evidence = {
        "azure_ad": {
            "users": [
                _user(
                    "low@x.us",
                    mfaStatus="disabled",
                    lastActiveInDays=35,
                ),
                _user(
                    "high@x.us",
                    mfaStatus="disabled",
                    assignedRoles=["Global Administrator"],
                    lastActiveInDays=120,
                ),
            ],
        }
    }
    findings = critical_findings.build_critical_findings(evidence)
    assert [f["userPrincipalName"] for f in findings] == ["high@x.us", "low@x.us"]
