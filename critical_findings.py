"""Compound-risk analysis across users.

The NIST mapper evaluates each control independently. An assessor scanning
the report, though, focuses first on accounts that hit *multiple* risk
factors at once — stale AND privileged AND no MFA is worse than three
separate findings. This module does that triangulation and produces a
severity-ranked list surfaced at the top of the report.
"""

from __future__ import annotations

from typing import Any

BREAK_GLASS_FACTOR = "break_glass"

FACTOR_LABELS = {
    "no_mfa": "no MFA",
    "standing_admin": "standing admin",
    "privileged": "privileged",
    "inactive_30": "inactive 30+ days",
    "inactive_90": "inactive 90+ days",
    "never_signed_in": "never signed in",
}

# Weights determine the severity rank. These are ordinal, not scientific.
FACTOR_WEIGHTS = {
    "no_mfa": 3,
    "standing_admin": 3,
    "privileged": 2,
    "inactive_90": 3,
    "inactive_30": 2,
    "never_signed_in": 2,
}


def _break_glass_set(evidence: dict[str, Any]) -> set[str]:
    raw = (evidence.get("exceptions") or {}).get("break_glass_upns") or []
    return {u.casefold() for u in raw if u}


def _pim_users(evidence: dict[str, Any]) -> set[str]:
    """UPNs that appear as PIM activators in the sampled audit window."""
    sample = ((evidence.get("azure_ad") or {}).get("auditLogs") or {}).get("sample") or []
    activators: set[str] = set()
    for entry in sample:
        name = (entry.get("activityDisplayName") or "").lower()
        if "pim activation" not in name or "completed" not in name:
            continue
        upn = entry.get("initiatedBy")
        if isinstance(upn, str) and "@" in upn:
            activators.add(upn)
    return activators


def _user_factors(
    user: dict[str, Any],
    break_glass: set[str],
    pim_activators: set[str],
) -> list[str]:
    upn = (user.get("userPrincipalName") or "").casefold()
    if upn in break_glass:
        return []
    if not user.get("accountEnabled"):
        return []
    factors: list[str] = []
    if user.get("mfaStatus") != "enabled":
        factors.append("no_mfa")
    roles = user.get("assignedRoles") or []
    if roles:
        factors.append("privileged")
    if "Global Administrator" in roles and (user.get("userPrincipalName") or "") not in pim_activators:
        factors.append("standing_admin")
    days = user.get("lastActiveInDays")
    if isinstance(days, int):
        if days > 90:
            factors.append("inactive_90")
        elif days > 30:
            factors.append("inactive_30")
    sign_in = user.get("signInActivity") or {}
    if not sign_in.get("lastSignInDateTime") and not sign_in.get("lastNonInteractiveSignInDateTime"):
        factors.append("never_signed_in")
    return factors


def _recommendation(factors: list[str]) -> str:
    fs = set(factors)
    if "standing_admin" in fs and "no_mfa" in fs:
        return "CRITICAL: privileged account without MFA. Register MFA or move to PIM-eligible and require it at activation."
    if "privileged" in fs and "no_mfa" in fs:
        return "Register MFA before any further privileged use."
    if "privileged" in fs and ("inactive_90" in fs or "inactive_30" in fs):
        return "Stale admin account. Disable, or rotate ownership and reduce to just-in-time PIM access."
    if "inactive_90" in fs:
        return "Hasn't signed in 90+ days. Disable or confirm off-boarding status."
    if "never_signed_in" in fs and "privileged" in fs:
        return "Privileged and never used. Either mark as break-glass in config, or disable."
    if "inactive_30" in fs:
        return "Consider disabling if the user is no longer active."
    return "Review and remediate."


def build_critical_findings(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a severity-ranked list of users with 2+ overlapping risk factors."""
    users = (evidence.get("azure_ad") or {}).get("users") or []
    break_glass = _break_glass_set(evidence)
    pim_activators = _pim_users(evidence)
    findings: list[dict[str, Any]] = []
    for user in users:
        factors = _user_factors(user, break_glass, pim_activators)
        if len(factors) < 2:
            continue
        severity = sum(FACTOR_WEIGHTS.get(f, 1) for f in factors)
        findings.append(
            {
                "userPrincipalName": user.get("userPrincipalName"),
                "displayName": user.get("displayName"),
                "factors": factors,
                "factorLabels": [FACTOR_LABELS[f] for f in factors if f in FACTOR_LABELS],
                "severity": severity,
                "recommendation": _recommendation(factors),
            }
        )
    findings.sort(key=lambda f: (-f["severity"], f["userPrincipalName"] or ""))
    return findings
