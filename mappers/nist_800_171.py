"""Map collected evidence to NIST 800-171 r2 control status.

Each ``_map_*`` helper returns a dict of the shape:
    {
        "title": str,
        "family": str,
        "description": str,
        "status": "COMPLIANT" | "PARTIAL" | "NOT_ADDRESSED",
        "maturity": "Automated" | "Manual Verification Needed" | "Not Addressed",
        "evidence": [{"source": str, "detail": str, "confidence": str}, ...],
        "gaps": [str, ...],
        "remediation": {
            "effort": str,
            "bucket": "quick_win" | "medium" | "heavy_lift",
            "steps": [str, ...],
        },
    }
"""

from __future__ import annotations

from typing import Any, Callable


STATUS_COMPLIANT = "COMPLIANT"
STATUS_PARTIAL = "PARTIAL"
STATUS_NOT_ADDRESSED = "NOT_ADDRESSED"

MATURITY_AUTOMATED = "Automated"
MATURITY_MANUAL = "Manual Verification Needed"
MATURITY_NONE = "Not Addressed"

BUCKET_QUICK = "quick_win"
BUCKET_MEDIUM = "medium"
BUCKET_HEAVY = "heavy_lift"

CONTROL_IDS = [
    "AC-1",
    "AC-2",
    "AC-3",
    "AC-6",
    "AT-1",
    "AU-1",
    "AU-2",
    "AU-3",
    "AU-6",
    "AU-12",
    "CM-1",
    "IA-1",
    "IA-2",
    "IA-4",
    "IA-5",
    "IR-1",
    "IR-4",
    "MA-1",
    "MP-1",
    "PE-1",
    "PS-1",
    "RA-1",
    "SC-1",
    "SC-7",
    "SI-1",
    "SI-2",
    "SI-3",
    "SI-4",
]

FAMILY_TITLES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CM": "Configuration Management",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical Protection",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}


def map(evidence: dict[str, Any]) -> dict[str, Any]:
    """Transform raw evidence into a control-status report."""
    mappers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
        "AC-1": _map_ac1,
        "AC-2": _map_ac2,
        "AC-3": _map_ac3,
        "AC-6": _map_ac6,
        "IA-2": _map_ia2,
        "IA-4": _map_ia4,
        "IA-5": _map_ia5,
        "AU-2": _map_au2,
        "AU-3": _map_au3,
        "AU-6": _map_au6,
        "AU-12": _map_au12,
        "SC-7": _map_sc7,
        "SI-2": _map_si2,
        "SI-3": _map_si3,
        "SI-4": _map_si4,
        "IR-1": _map_ir1,
        "IR-4": _map_ir4,
        "AT-1": _map_at1,
    }
    controls: dict[str, dict[str, Any]] = {}
    for control_id, fn in mappers.items():
        entry = fn(evidence)
        entry.setdefault("family", control_id.split("-")[0])
        controls[control_id] = entry
    for control_id, entry in _map_policy_only_controls(evidence).items():
        controls[control_id] = entry
    summary = _summarize(controls)
    return {"controls": controls, "summary": summary}


def generate_remediation_backlog(compliance_status: dict[str, Any]) -> dict[str, Any]:
    """Bucket remediation tasks by effort for a sortable backlog."""
    buckets: dict[str, list[dict[str, Any]]] = {
        BUCKET_QUICK: [],
        BUCKET_MEDIUM: [],
        BUCKET_HEAVY: [],
    }
    for control_id, control in compliance_status.get("controls", {}).items():
        if control["status"] == STATUS_COMPLIANT:
            continue
        remediation = control.get("remediation") or {}
        bucket = remediation.get("bucket", BUCKET_MEDIUM)
        buckets.setdefault(bucket, []).append(
            {
                "control": control_id,
                "title": control.get("title"),
                "description": "; ".join(control.get("gaps", [])) or control.get("title"),
                "effort": remediation.get("effort", "Unknown"),
                "steps": remediation.get("steps", []),
                "status": control["status"],
            }
        )
    return buckets


def _summarize(controls: dict[str, dict[str, Any]]) -> dict[str, Any]:
    compliant = sum(1 for c in controls.values() if c["status"] == STATUS_COMPLIANT)
    partial = sum(1 for c in controls.values() if c["status"] == STATUS_PARTIAL)
    not_addressed = sum(
        1 for c in controls.values() if c["status"] == STATUS_NOT_ADDRESSED
    )
    automated = sum(1 for c in controls.values() if c["maturity"] == MATURITY_AUTOMATED)
    total = len(controls) or 1
    overall = round(((compliant * 1.0 + partial * 0.5) / total) * 100)
    return {
        "compliant": compliant,
        "partial": partial,
        "notAddressed": not_addressed,
        "automatedMaturity": automated,
        "overallPercentage": overall,
    }


def _active_users(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    users = (evidence.get("azure_ad") or {}).get("users") or []
    return [u for u in users if u.get("accountEnabled")]


def _conditional_access(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return (evidence.get("azure_ad") or {}).get("conditionalAccessPolicies") or []


def _mfa_requiring_policies(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        p
        for p in policies
        if p.get("state") == "enabled"
        and any("mfa" in (c or "").lower() for c in p.get("grantControls", []) or [])
    ]


def _report_only_policies(
    policies: list[dict[str, Any]],
    predicate=None,
) -> list[dict[str, Any]]:
    """CA policies in ``enabledForReportingButNotEnforced`` state.

    Optional ``predicate`` narrows to policies whose shape would otherwise
    close a given control (e.g. MFA grant control, block grant control).
    """
    filtered = [
        p for p in policies
        if p.get("state") == "enabledForReportingButNotEnforced"
    ]
    if predicate is None:
        return filtered
    return [p for p in filtered if predicate(p)]


def _has_mfa_grant(policy: dict[str, Any]) -> bool:
    return any("mfa" in (c or "").lower() for c in policy.get("grantControls", []) or [])


def _has_block_or_compliant_grant(policy: dict[str, Any]) -> bool:
    return any(
        "block" in (c or "").lower() or "compliantdevice" in (c or "").lower()
        for c in policy.get("grantControls", []) or []
    )


def _report_only_evidence_and_gap(
    entry: dict[str, Any],
    report_only: list[dict[str, Any]],
    topic: str,
) -> None:
    """Add an evidence line and (if the entry is otherwise compliant) a gap
    pointing out that some policies matching this topic are sitting in
    report-only mode and not actually enforcing."""
    if not report_only:
        return
    names = ", ".join(p.get("displayName", "unnamed") for p in report_only[:3])
    more = f" (+{len(report_only) - 3} more)" if len(report_only) > 3 else ""
    entry["evidence"].append(
        _evidence(
            "Azure AD",
            f"{len(report_only)} {topic} policies in report-only mode (not enforcing): {names}{more}",
            confidence="Medium",
        )
    )
    if entry["status"] == STATUS_COMPLIANT:
        entry["status"] = STATUS_PARTIAL
    entry["gaps"].append(
        f"{len(report_only)} {topic} conditional-access policies are in "
        "report-only mode. Promote to 'enabled' once you've verified "
        "they don't break legitimate sign-ins."
    )


def _evidence(source: str, detail: str, confidence: str = "High") -> dict[str, str]:
    return {"source": source, "detail": detail, "confidence": confidence}


def _name_list(users: list[dict[str, Any]], limit: int = 5) -> str:
    names = [u.get("userPrincipalName") or u.get("displayName") or "unknown" for u in users[:limit]]
    suffix = f" (+{len(users) - limit} more)" if len(users) > limit else ""
    return ", ".join(names) + suffix


def _privileged_users(users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [u for u in users if u.get("assignedRoles")]


def _break_glass_upns(evidence: dict[str, Any]) -> set[str]:
    raw = (evidence.get("exceptions") or {}).get("break_glass_upns") or []
    return {u.casefold() for u in raw if u}


def _is_break_glass(user: dict[str, Any], break_glass: set[str]) -> bool:
    upn = (user.get("userPrincipalName") or "").casefold()
    return bool(upn) and upn in break_glass


def _pim_activators(evidence: dict[str, Any]) -> dict[str, int]:
    """Return a map of UPN -> count of PIM role activations observed in
    the sampled audit-log window. The ``Add member to role completed
    (PIM activation)`` event is the definitive signal — it only fires
    after the activator satisfied approvals, MFA, and justification.
    """
    sample = ((evidence.get("azure_ad") or {}).get("auditLogs") or {}).get("sample") or []
    counts: dict[str, int] = {}
    for entry in sample:
        name = (entry.get("activityDisplayName") or "").lower()
        if "pim activation" not in name or "completed" not in name:
            continue
        upn = entry.get("initiatedBy")
        if isinstance(upn, str) and "@" in upn:
            counts[upn] = counts.get(upn, 0) + 1
    return counts


def _suspected_break_glass(user: dict[str, Any]) -> bool:
    """Heuristic: enabled, has a privileged role, has never signed in."""
    if not user.get("accountEnabled"):
        return False
    if not user.get("assignedRoles"):
        return False
    sign_in = user.get("signInActivity") or {}
    return not sign_in.get("lastSignInDateTime") and not sign_in.get(
        "lastNonInteractiveSignInDateTime"
    )


def _remediation(
    effort: str,
    bucket: str,
    steps: list[str],
) -> dict[str, Any]:
    return {"effort": effort, "bucket": bucket, "steps": steps}


def _base(
    title: str,
    family: str,
    description: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "family": family,
        "description": description,
        "status": STATUS_NOT_ADDRESSED,
        "maturity": MATURITY_NONE,
        "evidence": [],
        "gaps": [],
        "remediation": _remediation("Unknown", BUCKET_MEDIUM, []),
    }


def _map_ac1(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Access Control Policy and Procedures",
        "AC",
        "Documented, communicated, and reviewed access control policy.",
    )
    ca_policies = _conditional_access(evidence)
    mfa_policies = _mfa_requiring_policies(ca_policies)
    if mfa_policies:
        entry["evidence"].append(
            _evidence(
                "Azure AD conditional access",
                f"{len(mfa_policies)} enabled MFA conditional-access policies found",
            )
        )
        entry["status"] = STATUS_PARTIAL
        entry["maturity"] = MATURITY_MANUAL
        entry["gaps"].append(
            "Written access control policy document not verified by this tool."
        )
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            [
                "Write a 1-page access control policy covering account lifecycle, "
                "privilege assignment, and review cadence.",
                "Publish to shared drive and require annual acknowledgement.",
            ],
        )
    else:
        entry["gaps"].append("No enabled conditional-access policies enforcing MFA.")
        entry["remediation"] = _remediation(
            "2 hours",
            BUCKET_QUICK,
            [
                "Create a conditional-access policy requiring MFA for all users.",
                "Write a 1-page access control policy.",
            ],
        )
    _apply_policy_doc_evidence(entry, evidence, "AC-1")
    _report_only_evidence_and_gap(
        entry,
        _report_only_policies(ca_policies, _has_mfa_grant),
        topic="MFA",
    )
    return entry


def _map_ac2(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Account Management",
        "AC",
        "Manage information system accounts: creation, disabling, removal.",
    )
    active = _active_users(evidence)
    break_glass = _break_glass_upns(evidence)
    non_bg = [u for u in active if not _is_break_glass(u, break_glass)]
    mfa_enabled = [u for u in non_bg if u.get("mfaStatus") == "enabled"]
    inactive = [
        u
        for u in non_bg
        if isinstance(u.get("lastActiveInDays"), int)
        and u["lastActiveInDays"] > 30
    ]

    privileged_inactive = _privileged_users(inactive)

    entry["evidence"] = [
        _evidence("Azure AD", f"{len(non_bg)} active users (excluding break-glass)"),
        _evidence("Azure AD", f"{len(mfa_enabled)}/{len(non_bg)} users with MFA registered"),
        _evidence("Azure AD", f"{len(inactive)} inactive users (>30 days since sign-in)"),
    ]
    if privileged_inactive:
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"CRITICAL: {len(privileged_inactive)} privileged account(s) inactive >30 days: {_name_list(privileged_inactive)}",
                confidence="High",
            )
        )
    entry["maturity"] = MATURITY_AUTOMATED
    compliant = not inactive and len(mfa_enabled) == len(non_bg) and non_bg
    if compliant:
        entry["status"] = STATUS_COMPLIANT
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    else:
        entry["status"] = STATUS_PARTIAL if active else STATUS_NOT_ADDRESSED
        if privileged_inactive:
            entry["gaps"].append(
                f"Privileged account(s) inactive >30 days — disable or reassign: {_name_list(privileged_inactive)}"
            )
        other_inactive = [u for u in inactive if u not in privileged_inactive]
        if other_inactive:
            entry["gaps"].append(
                f"{len(other_inactive)} other inactive account(s): {_name_list(other_inactive)}"
            )
        if len(mfa_enabled) < len(non_bg):
            missing_mfa = [u for u in non_bg if u.get("mfaStatus") != "enabled"]
            entry["gaps"].append(
                f"{len(missing_mfa)} active user(s) without MFA: {_name_list(missing_mfa)}"
            )
        steps: list[str] = []
        if inactive:
            steps.append(
                f"Disable or reassign {len(inactive)} inactive account(s) in Entra admin center."
            )
        if len(mfa_enabled) < len(non_bg):
            steps.append("Register MFA for remaining active users.")
        entry["remediation"] = _remediation(
            "30 minutes" if len(steps) <= 1 else "1-2 hours",
            BUCKET_QUICK,
            steps,
        )
    return entry


def _map_ac3(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Access Enforcement",
        "AC",
        "Enforce approved authorizations for logical access to systems.",
    )
    ca_policies = _conditional_access(evidence)
    enabled = [p for p in ca_policies if p.get("state") == "enabled"]
    if enabled:
        entry["status"] = STATUS_COMPLIANT
        entry["maturity"] = MATURITY_AUTOMATED
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"{len(enabled)} enabled conditional-access policies enforcing access decisions.",
            )
        )
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    else:
        entry["status"] = STATUS_NOT_ADDRESSED
        entry["gaps"].append("No enabled conditional-access policies.")
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            ["Create conditional-access policy requiring MFA for all users/apps."],
        )
    _report_only_evidence_and_gap(
        entry,
        _report_only_policies(ca_policies),
        topic="access-control",
    )
    return entry


def _map_ac6(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Least Privilege",
        "AC",
        "Employ the principle of least privilege for administrative access.",
    )
    active = _active_users(evidence)
    privileged = _privileged_users(active)
    global_admins = [
        u for u in privileged if "Global Administrator" in (u.get("assignedRoles") or [])
    ]
    pim_counts = _pim_activators(evidence)
    pim_users = set(pim_counts.keys())
    # Classify Global Admins: anyone who appears as a PIM activator in the
    # sampled window is JIT-managed (the static role snapshot caught them
    # mid-activation). The rest are standing assignments.
    jit_admins = [
        u for u in global_admins
        if (u.get("userPrincipalName") or "") in pim_users
    ]
    standing_admins = [u for u in global_admins if u not in jit_admins]

    entry["evidence"] = [
        _evidence("Azure AD", f"{len(privileged)} users hold one or more privileged roles"),
    ]
    if standing_admins:
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"{len(standing_admins)} standing Global Administrator(s): {_name_list(standing_admins)}",
            )
        )
    if jit_admins:
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"{len(jit_admins)} Global Admin(s) use PIM just-in-time activation: {_name_list(jit_admins)} — stronger AC-6 posture than standing assignment",
            )
        )
    if pim_counts:
        total = sum(pim_counts.values())
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"PIM activity: {total} activation(s) by {len(pim_counts)} principal(s) in sampled audit window",
            )
        )
    entry["maturity"] = MATURITY_AUTOMATED
    standing_count = len(standing_admins)
    if 1 <= standing_count <= 2 and len(privileged) <= max(2, int(len(active) * 0.3) + 1):
        entry["status"] = STATUS_COMPLIANT
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    else:
        entry["status"] = STATUS_PARTIAL
        if standing_count > 2:
            entry["gaps"].append(
                f"{standing_count} standing Global Administrators ({_name_list(standing_admins)}) — "
                "recommend 2 or fewer standing assignments (move the rest to PIM-eligible)."
            )
        if standing_count == 0 and not jit_admins:
            entry["gaps"].append("No Global Administrator detected — verify tenant access.")
        entry["remediation"] = _remediation(
            "2 hours",
            BUCKET_QUICK,
            [
                "Move standing Global Admin assignments to PIM-eligible (require activation).",
                "Document break-glass account ownership and add to exceptions list.",
            ],
        )
    return entry


def _map_ia2(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Identification and Authentication (Users)",
        "IA",
        "Uniquely identify and authenticate users and devices.",
    )
    active = _active_users(evidence)
    break_glass = _break_glass_upns(evidence)
    mfa_enabled = [u for u in active if u.get("mfaStatus") == "enabled"]
    mfa_missing = [
        u for u in active
        if u.get("mfaStatus") != "enabled" and not _is_break_glass(u, break_glass)
    ]
    break_glass_users = [u for u in active if _is_break_glass(u, break_glass)]
    privileged_missing = _privileged_users(mfa_missing)
    mfa_policies = _mfa_requiring_policies(_conditional_access(evidence))
    entry["evidence"] = [
        _evidence(
            "Azure AD",
            f"{len(mfa_enabled)}/{len(active)} active users with MFA registered",
        ),
        _evidence(
            "Azure AD",
            f"{len(mfa_policies)} conditional-access policies enforcing MFA",
        ),
    ]
    if privileged_missing:
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"CRITICAL: {len(privileged_missing)} privileged account(s) without MFA: {_name_list(privileged_missing)}",
                confidence="High",
            )
        )
    if break_glass_users:
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"{len(break_glass_users)} break-glass account(s) excepted per config: {_name_list(break_glass_users)}",
            )
        )
    suspected = [
        u for u in active
        if _suspected_break_glass(u) and not _is_break_glass(u, break_glass)
    ]
    if suspected:
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"Suspected break-glass account(s) (never-signed-in privileged): {_name_list(suspected)}. "
                "Add to exceptions.break_glass_upns in config to except from MFA gaps.",
                confidence="Medium",
            )
        )
    entry["maturity"] = MATURITY_AUTOMATED
    non_bg_active = [u for u in active if not _is_break_glass(u, break_glass)]
    non_bg_mfa_enabled = [u for u in non_bg_active if u.get("mfaStatus") == "enabled"]
    if non_bg_active and len(non_bg_mfa_enabled) == len(non_bg_active) and mfa_policies:
        entry["status"] = STATUS_COMPLIANT
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    elif mfa_policies:
        entry["status"] = STATUS_PARTIAL
        if privileged_missing:
            entry["gaps"].append(
                f"Privileged account(s) without MFA — resolve before anything else: {_name_list(privileged_missing)}"
            )
        other_missing = [u for u in mfa_missing if u not in privileged_missing]
        if other_missing:
            entry["gaps"].append(
                f"{len(other_missing)} other active user(s) without MFA: {_name_list(other_missing)}"
            )
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            ["Require remaining users to register MFA on next sign-in."],
        )
    else:
        entry["status"] = STATUS_NOT_ADDRESSED
        entry["gaps"].append("No MFA-requiring conditional-access policies enabled.")
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            ["Enable a conditional-access policy that requires MFA for all users."],
        )
    _report_only_evidence_and_gap(
        entry,
        _report_only_policies(_conditional_access(evidence), _has_mfa_grant),
        topic="MFA",
    )
    return entry


def _map_ia4(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Identifier Management",
        "IA",
        "Manage user identifiers: unique, disabled when no longer needed.",
    )
    users = (evidence.get("azure_ad") or {}).get("users") or []
    disabled = [u for u in users if not u.get("accountEnabled")]
    entry["evidence"] = [
        _evidence(
            "Azure AD",
            f"{len(users)} total identifiers, {len(disabled)} disabled accounts retained for audit.",
        )
    ]
    entry["maturity"] = MATURITY_AUTOMATED
    entry["status"] = STATUS_COMPLIANT
    entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    return entry


def _map_ia5(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Authenticator Management",
        "IA",
        "Manage authenticators: complexity, rotation, storage.",
    )
    policy = (evidence.get("azure_ad") or {}).get("passwordPolicy") or {}
    min_length = policy.get("minimumPasswordLength") or 0
    complexity = bool(policy.get("requiresComplexity"))
    entry["evidence"] = [
        _evidence(
            "Azure AD password policy",
            f"Minimum length {min_length}, complexity={complexity}",
        ),
    ]
    entry["maturity"] = MATURITY_AUTOMATED
    if min_length >= 12 and complexity:
        entry["status"] = STATUS_COMPLIANT
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    else:
        entry["status"] = STATUS_PARTIAL
        entry["gaps"].append("Password policy does not meet 12+ char complexity baseline.")
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            ["Configure Entra password protection to enforce 12+ character minimum."],
        )
    return entry


def _map_au2(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Audit Events",
        "AU",
        "Determine auditable events and event categories.",
    )
    audit = (evidence.get("azure_ad") or {}).get("auditLogs") or {}
    sample = audit.get("sample") or []
    entry["evidence"] = [
        _evidence("Azure AD audit", f"{len(sample)} recent directory-audit events observed"),
    ]
    if audit.get("logsAvailable") and sample:
        entry["status"] = STATUS_COMPLIANT
        entry["maturity"] = MATURITY_AUTOMATED
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    else:
        entry["status"] = STATUS_PARTIAL
        entry["gaps"].append("Directory audit log not readable or empty.")
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            ["Verify Entra audit retention and grant AuditLog.Read.All to the app."],
        )
    return entry


def _map_au3(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Content of Audit Records",
        "AU",
        "Audit records contain sufficient detail: who, what, when, where.",
    )
    sample = ((evidence.get("azure_ad") or {}).get("auditLogs") or {}).get("sample") or []
    if sample:
        first = sample[0]
        has_who = bool(first.get("initiatedBy"))
        has_what = bool(first.get("activityDisplayName") or first.get("operationType"))
        has_when = bool(first.get("activityDateTime"))
        complete = has_who and has_what and has_when
        entry["evidence"] = [
            _evidence(
                "Azure AD audit",
                f"Sample record fields: who={has_who}, what={has_what}, when={has_when}",
            ),
        ]
        entry["status"] = STATUS_COMPLIANT if complete else STATUS_PARTIAL
        entry["maturity"] = MATURITY_AUTOMATED
        entry["remediation"] = (
            _remediation("None", BUCKET_QUICK, [])
            if complete
            else _remediation(
                "1 hour",
                BUCKET_QUICK,
                ["Verify audit record completeness via Entra Monitoring settings."],
            )
        )
    else:
        entry["status"] = STATUS_NOT_ADDRESSED
        entry["gaps"].append("No audit sample available.")
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            ["Grant AuditLog.Read.All and re-run the collector."],
        )
    return entry


def _map_au6(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Audit Review, Analysis, and Reporting",
        "AU",
        "Review and analyze audit records for inappropriate activity.",
    )
    entry["status"] = STATUS_PARTIAL
    entry["maturity"] = MATURITY_MANUAL
    entry["evidence"].append(
        _evidence(
            "Azure AD",
            "Audit data is collected; review cadence must be documented manually.",
        )
    )
    entry["gaps"].append("No automated evidence of recurring review or escalation process.")
    entry["remediation"] = _remediation(
        "1 day",
        BUCKET_MEDIUM,
        [
            "Document weekly audit-review procedure and assign an owner.",
            "Configure Sentinel or Log Analytics alerts for privileged operations.",
        ],
    )
    return entry


def _map_au12(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Audit Generation",
        "AU",
        "Generate audit records for defined events across all components.",
    )
    azure_audit = ((evidence.get("azure_ad") or {}).get("auditLogs") or {})
    azure_ok = bool(azure_audit.get("logsAvailable"))
    exchange_audit = ((evidence.get("exchange") or {}).get("exchangeAuditLog") or {})
    exchange_events = exchange_audit.get("eventCount") or 0
    entry["evidence"] = []
    if azure_ok:
        entry["evidence"].append(
            _evidence(
                "Azure AD",
                f"Tenant-wide directory audit readable ({azure_audit.get('retentionDays', 'unknown')}-day retention). "
                "Covers admin/config events across Entra, Intune, and Exchange-admin surfaces.",
            )
        )
    else:
        entry["evidence"].append(
            _evidence("Azure AD", "Directory audit not readable — cannot verify audit generation.")
        )
    if exchange_events:
        entry["evidence"].append(
            _evidence(
                "Exchange",
                f"{exchange_events} Exchange-service admin event(s) observed in directoryAudits sample.",
            )
        )
    else:
        entry["evidence"].append(
            _evidence(
                "Exchange",
                "No Exchange-service admin events in the sampled directoryAudits window — typical for small tenants.",
                confidence="Medium",
            )
        )
    entry["evidence"].append(
        _evidence(
            "Purview",
            "Mailbox-item-level audit (MailItemsAccessed, Send, etc.) is not exposed via Graph — verify "
            "the Purview unified audit log is enabled for CUI-related mailboxes.",
            confidence="Medium",
        )
    )
    if azure_ok:
        entry["status"] = STATUS_PARTIAL
        entry["maturity"] = MATURITY_AUTOMATED
        entry["gaps"].append(
            "Confirm Purview unified audit log is enabled (not verifiable via Graph)."
        )
        entry["remediation"] = _remediation(
            "30 minutes",
            BUCKET_QUICK,
            ["Verify Purview unified audit log is on: Security.microsoft.us > Audit > Start recording."],
        )
    else:
        entry["status"] = STATUS_NOT_ADDRESSED
        entry["remediation"] = _remediation(
            "1 day",
            BUCKET_MEDIUM,
            ["Enable unified audit log and grant AuditLog.Read.All to the collector."],
        )
    return entry


def _map_sc7(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Boundary Protection",
        "SC",
        "Monitor and control communications at external boundaries.",
    )
    ca_policies = _conditional_access(evidence)
    geo_policies = [
        p
        for p in ca_policies
        if p.get("state") == "enabled" and _has_block_or_compliant_grant(p)
    ]
    entry["evidence"].append(
        _evidence(
            "Azure AD",
            f"{len(geo_policies)} conditional-access policies restricting boundary access.",
        )
    )
    if geo_policies:
        entry["status"] = STATUS_PARTIAL
        entry["maturity"] = MATURITY_MANUAL
        entry["gaps"].append("Network-level boundary enforcement must be verified manually.")
    else:
        entry["status"] = STATUS_NOT_ADDRESSED
        entry["gaps"].append("No block or device-compliance conditional-access policies found.")
    _report_only_evidence_and_gap(
        entry,
        _report_only_policies(ca_policies, _has_block_or_compliant_grant),
        topic="boundary",
    )
    entry["remediation"] = _remediation(
        "1 day",
        BUCKET_MEDIUM,
        [
            "Create conditional-access policy blocking legacy authentication.",
            "Require compliant device for CUI-containing applications.",
        ],
    )
    return entry


def _map_si2(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Flaw Remediation",
        "SI",
        "Identify, report, and correct system flaws in a timely manner.",
    )
    devices = (evidence.get("intune") or {}).get("devices") or []
    compliant_devices = [d for d in devices if d.get("complianceState") == "compliant"]
    old_devices = [
        d
        for d in devices
        if _version_tuple(d.get("osVersion")) and _version_tuple(d.get("osVersion")) < (14, 3)
    ]
    entry["evidence"] = [
        _evidence(
            "Intune",
            f"{len(compliant_devices)}/{len(devices)} managed devices compliant",
        ),
        _evidence(
            "Intune",
            f"{len(old_devices)} devices on macOS versions below 14.3",
        ),
    ]
    if devices and not old_devices and len(compliant_devices) == len(devices):
        entry["status"] = STATUS_COMPLIANT
        entry["maturity"] = MATURITY_AUTOMATED
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    elif devices:
        entry["status"] = STATUS_PARTIAL
        if old_devices:
            entry["gaps"].append(f"{len(old_devices)} devices below macOS 14.3.")
        if len(compliant_devices) < len(devices):
            entry["gaps"].append(
                f"{len(devices) - len(compliant_devices)} non-compliant devices."
            )
        entry["remediation"] = _remediation(
            "1 day",
            BUCKET_MEDIUM,
            [
                "Push software-update policy requiring macOS 14.3+.",
                "Remediate non-compliant devices via Intune company portal.",
            ],
        )
    else:
        entry["status"] = STATUS_NOT_ADDRESSED
        entry["gaps"].append("No managed devices visible via Intune.")
        entry["remediation"] = _remediation(
            "3 days",
            BUCKET_HEAVY,
            ["Enroll all endpoints into Intune."],
        )
    return entry


def _map_si3(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Malicious Code Protection",
        "SI",
        "Deploy and maintain malicious-code protection on all endpoints.",
    )
    av = (evidence.get("defender") or {}).get("antivirusStatus") or {}
    healthy = av.get("agentHealthy", 0)
    unhealthy = av.get("agentNotHealthy", 0)
    threats = (evidence.get("defender") or {}).get("threatDetections") or {}
    active = threats.get("activeThreats", 0)
    entry["evidence"] = [
        _evidence(
            "Defender (via Intune)",
            f"{healthy} endpoints with healthy antivirus agent, {unhealthy} unhealthy.",
        ),
        _evidence("Defender", f"{active} active threats in past 90 days."),
    ]
    if healthy and not unhealthy and not active:
        entry["status"] = STATUS_COMPLIANT
        entry["maturity"] = MATURITY_AUTOMATED
        entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
    else:
        entry["status"] = STATUS_PARTIAL
        if unhealthy:
            entry["gaps"].append(f"{unhealthy} endpoints with unhealthy AV agent.")
        if active:
            entry["gaps"].append(f"{active} unresolved Defender alerts in past 90 days.")
        entry["remediation"] = _remediation(
            "4 hours",
            BUCKET_MEDIUM,
            [
                "Remediate unhealthy Defender agents.",
                "Triage and close outstanding Defender alerts.",
            ],
        )
    return entry


def _map_si4(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "System Monitoring",
        "SI",
        "Monitor events on the system to detect attacks and indicators.",
    )
    secure_score = (evidence.get("defender") or {}).get("secureScore") or {}
    current = secure_score.get("currentScore")
    maximum = secure_score.get("maxScore")
    if current is not None and maximum:
        percentage = round((current / maximum) * 100)
        entry["evidence"].append(
            _evidence(
                "Microsoft Secure Score",
                f"Secure Score: {current}/{maximum} ({percentage}%)",
            )
        )
        entry["maturity"] = MATURITY_AUTOMATED
        if percentage >= 70:
            entry["status"] = STATUS_COMPLIANT
            entry["remediation"] = _remediation("None", BUCKET_QUICK, [])
        else:
            entry["status"] = STATUS_PARTIAL
            entry["gaps"].append(f"Secure Score {percentage}% is below 70% target.")
            entry["remediation"] = _remediation(
                "1 week",
                BUCKET_HEAVY,
                ["Work through Secure Score recommended improvements in priority order."],
            )
    else:
        entry["status"] = STATUS_NOT_ADDRESSED
        entry["gaps"].append("Secure Score data unavailable.")
        entry["remediation"] = _remediation(
            "1 hour",
            BUCKET_QUICK,
            ["Grant SecurityEvents.Read.All and re-run the collector."],
        )
    return entry


def _map_ir1(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Incident Response Policy",
        "IR",
        "Documented, reviewed, and tested incident response policy and procedures.",
    )
    entry["status"] = STATUS_NOT_ADDRESSED
    entry["maturity"] = MATURITY_NONE
    entry["gaps"].append(
        "No automated evidence: requires a written incident response plan."
    )
    entry["remediation"] = _remediation(
        "2 days",
        BUCKET_HEAVY,
        [
            "Draft incident response plan: detect, contain, eradicate, recover.",
            "Define roles, responsibilities, and escalation contacts.",
            "Run one table-top exercise and document lessons learned.",
        ],
    )
    _apply_policy_doc_evidence(entry, evidence, "IR-1")
    return entry


def _map_ir4(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Incident Handling",
        "IR",
        "Coordinated incident-handling capability with detection, analysis, containment.",
    )
    threats = (evidence.get("defender") or {}).get("threatDetections") or {}
    resolved = threats.get("resolvedInPast90Days", 0)
    entry["evidence"].append(
        _evidence(
            "Defender",
            f"{resolved} threats resolved in past 90 days (tooling present)",
        )
    )
    entry["status"] = STATUS_PARTIAL
    entry["maturity"] = MATURITY_MANUAL
    entry["gaps"].append(
        "Incident-handling runbooks must be documented and tabletop-tested."
    )
    entry["remediation"] = _remediation(
        "3 days",
        BUCKET_HEAVY,
        [
            "Create runbooks for top 3 incident types (phishing, malware, data leak).",
            "Conduct one tabletop exercise and capture action items.",
        ],
    )
    return entry


def _map_at1(evidence: dict[str, Any]) -> dict[str, Any]:
    entry = _base(
        "Security Awareness Training",
        "AT",
        "Deliver security awareness training to all users.",
    )
    entry["status"] = STATUS_NOT_ADDRESSED
    entry["maturity"] = MATURITY_NONE
    entry["gaps"].append(
        "No automated signal: track completion in an LMS or Attack Simulation Training."
    )
    entry["remediation"] = _remediation(
        "2 days",
        BUCKET_MEDIUM,
        [
            "Deploy Microsoft Attack Simulation Training or equivalent LMS.",
            "Require annual completion and retain certificates.",
        ],
    )
    _apply_policy_doc_evidence(entry, evidence, "AT-1")
    return entry


POLICY_ONLY_CONTROLS = {
    "AU-1": ("AU", "Audit and Accountability Policy",
             "Documented audit and accountability policy and procedures."),
    "CM-1": ("CM", "Configuration Management Policy",
             "Documented configuration management and change control policy."),
    "IA-1": ("IA", "Identification and Authentication Policy",
             "Documented identification and authentication policy."),
    "MA-1": ("MA", "System Maintenance Policy",
             "Documented system maintenance policy and procedures."),
    "MP-1": ("MP", "Media Protection Policy",
             "Documented media protection and removable-media handling policy."),
    "PE-1": ("PE", "Physical Protection Policy",
             "Documented physical and environmental protection policy."),
    "PS-1": ("PS", "Personnel Security Policy",
             "Documented personnel security policy covering screening and access."),
    "RA-1": ("RA", "Risk Assessment Policy",
             "Documented risk assessment and risk management policy."),
    "SC-1": ("SC", "System and Communications Protection Policy",
             "Documented system and communications protection policy."),
    "SI-1": ("SI", "System and Information Integrity Policy",
             "Documented system and information integrity policy."),
}


def _policy_docs_for(evidence: dict[str, Any], control_id: str) -> list[dict[str, Any]]:
    matches = (evidence.get("policies") or {}).get("controlMatches") or {}
    return matches.get(control_id) or []


def _apply_policy_doc_evidence(
    entry: dict[str, Any],
    evidence: dict[str, Any],
    control_id: str,
) -> None:
    docs = _policy_docs_for(evidence, control_id)
    if not docs:
        return
    names = ", ".join(d.get("name") for d in docs if d.get("name"))
    entry["evidence"].append(
        _evidence(
            "SharePoint policies library",
            f"Matched policy document(s): {names}",
        )
    )
    entry["gaps"] = [
        g for g in entry["gaps"]
        if "written" not in g.lower() and "policy document" not in g.lower()
    ]
    if entry["status"] != STATUS_COMPLIANT:
        entry["status"] = STATUS_PARTIAL if entry["status"] == STATUS_NOT_ADDRESSED else entry["status"]
    if entry["status"] == STATUS_PARTIAL and entry["gaps"] == []:
        entry["status"] = STATUS_COMPLIANT
        entry["maturity"] = MATURITY_AUTOMATED


def _map_policy_only_controls(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    policies_block = evidence.get("policies") or {}
    site_available = bool(policies_block.get("available"))
    for control_id, (family, title, description) in POLICY_ONLY_CONTROLS.items():
        entry = _base(title, family, description)
        docs = _policy_docs_for(evidence, control_id)
        if docs:
            names = ", ".join(d.get("name") for d in docs if d.get("name"))
            entry["evidence"].append(
                _evidence(
                    "SharePoint policies library",
                    f"Matched policy document(s): {names}",
                )
            )
            entry["status"] = STATUS_COMPLIANT
            entry["maturity"] = MATURITY_AUTOMATED
            entry["remediation"] = _remediation("0 hours", BUCKET_QUICK, [])
        else:
            reason = (
                "No matching policy document found in configured SharePoint library."
                if site_available
                else "Policies collector not configured or SharePoint library unreachable."
            )
            entry["gaps"].append(reason)
            entry["remediation"] = _remediation(
                "1 day",
                BUCKET_MEDIUM,
                [
                    f"Draft a 1–2 page {title}.",
                    "Publish to the SharePoint policies library used by this tool.",
                    "Require annual review and executive sign-off.",
                ],
            )
        results[control_id] = entry
    return results


def _version_tuple(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    parts: list[int] = []
    for piece in version.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            break
    return tuple(parts) if parts else None
