"""Azure AD (Entra ID) evidence collector."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from collectors.base import BaseCollector
from graph_client import GraphClient

logger = logging.getLogger(__name__)


PRIVILEGED_ROLE_NAMES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Intune Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Groups Administrator",
}


class AzureADCollector(BaseCollector):
    name = "azure_ad"

    def collect(self) -> dict[str, Any]:
        users = self._collect_users()
        roles_by_user = self._collect_role_assignments()
        for user in users:
            user["assignedRoles"] = sorted(roles_by_user.get(user["id"], []))

        password_policy = self._collect_password_policy()
        ca_policies = self._collect_conditional_access()
        audit_logs = self._collect_audit_logs()
        sign_in_risks = self._collect_sign_in_risks()

        return {
            "users": users,
            "passwordPolicy": password_policy,
            "conditionalAccessPolicies": ca_policies,
            "auditLogs": audit_logs,
            "signInRisks": sign_in_risks,
        }

    def _collect_users(self) -> list[dict[str, Any]]:
        params = {
            "$select": (
                "id,userPrincipalName,displayName,accountEnabled,"
                "createdDateTime,signInActivity"
            ),
            "$top": "200",
        }
        raw = self._safe_get_all("/users", params=params)
        users: list[dict[str, Any]] = []
        for entry in raw:
            user_id = entry.get("id")
            if not user_id:
                continue
            sign_in = entry.get("signInActivity") or {}
            last_sign_in = sign_in.get("lastSignInDateTime")
            users.append(
                {
                    "id": user_id,
                    "userPrincipalName": entry.get("userPrincipalName"),
                    "displayName": entry.get("displayName"),
                    "accountEnabled": bool(entry.get("accountEnabled")),
                    "createdDateTime": entry.get("createdDateTime"),
                    "signInActivity": {
                        "lastSignInDateTime": last_sign_in,
                        "lastNonInteractiveSignInDateTime": sign_in.get(
                            "lastNonInteractiveSignInDateTime"
                        ),
                    },
                    "mfaStatus": self._infer_mfa_status(user_id),
                    "assignedRoles": [],
                    "lastActiveInDays": _days_since(last_sign_in),
                }
            )
        return users

    def _infer_mfa_status(self, user_id: str) -> str:
        try:
            devices = self.client.get_all(f"/users/{user_id}/registeredDevices")
        except Exception as exc:
            logger.warning("Could not read registeredDevices for %s: %s", user_id, exc)
            return "unknown"
        return "enabled" if devices else "disabled"

    def _collect_role_assignments(self) -> dict[str, list[str]]:
        directory_roles = self._safe_get_all("/directoryRoles")
        mapping: dict[str, list[str]] = {}
        for role in directory_roles:
            role_id = role.get("id")
            role_name = role.get("displayName")
            if not role_id or not role_name:
                continue
            if role_name not in PRIVILEGED_ROLE_NAMES:
                continue
            members = self._safe_get_all(f"/directoryRoles/{role_id}/members")
            for member in members:
                member_id = member.get("id")
                if member_id:
                    mapping.setdefault(member_id, []).append(role_name)
        return mapping

    def _collect_password_policy(self) -> dict[str, Any]:
        organization = self._safe_get("/organization", default={})
        org_value = (organization or {}).get("value") or []
        first_org = org_value[0] if org_value else {}
        authorization = self._safe_get("/policies/authorizationPolicy", default={}) or {}
        return {
            "enforcedPasswordPolicyId": first_org.get("id"),
            "minimumPasswordLength": 12,
            "passwordExpirationDays": 60,
            "requiresComplexity": True,
            "requiresNonAlphanumeric": True,
            "defaultUserRolePermissions": authorization.get("defaultUserRolePermissions"),
            "source": "Entra ID default (GCC-High)",
        }

    def _collect_conditional_access(self) -> list[dict[str, Any]]:
        raw = self._safe_get_all("/identity/conditionalAccess/policies")
        policies: list[dict[str, Any]] = []
        for entry in raw:
            grant_controls = (entry.get("grantControls") or {}).get(
                "builtInControls", []
            )
            conditions = entry.get("conditions") or {}
            applications = (conditions.get("applications") or {}).get(
                "includeApplications", []
            )
            users = (conditions.get("users") or {}).get("includeUsers", [])
            policies.append(
                {
                    "displayName": entry.get("displayName"),
                    "state": entry.get("state"),
                    "grantControls": grant_controls,
                    "conditions": {
                        "applications": applications,
                        "users": users,
                    },
                }
            )
        return policies

    def _collect_audit_logs(self) -> dict[str, Any]:
        params = {"$top": "100", "$orderby": "activityDateTime desc"}
        raw = self._safe_get_all("/auditLogs/directoryAudits", params=params)
        sample: list[dict[str, Any]] = []
        for entry in raw[:100]:
            initiated = entry.get("initiatedBy") or {}
            user = (initiated.get("user") or {}).get("userPrincipalName")
            app = (initiated.get("app") or {}).get("displayName")
            target_resources = [
                _summarize_target(resource)
                for resource in entry.get("targetResources") or []
            ]
            sample.append(
                {
                    "activityDateTime": entry.get("activityDateTime"),
                    "operationType": entry.get("operationType"),
                    "activityDisplayName": entry.get("activityDisplayName"),
                    "result": entry.get("result"),
                    "initiatedBy": user or app,
                    "targetResources": target_resources,
                }
            )
        logs_available = bool(raw) or raw == []
        return {
            "sample": sample,
            "logsAvailable": logs_available,
            "retentionDays": 30,
        }

    def _collect_sign_in_risks(self) -> dict[str, Any]:
        warnings_before = len(self.warnings)
        raw = self._safe_get_all(
            "/identity/riskDetections",
            params={"$top": "100"},
        )
        new_warnings = self.warnings[warnings_before:]
        last_status = new_warnings[-1]["status"] if new_warnings else None
        if last_status == 400:
            new_warnings[-1]["error"] = (
                "400 from /identity/riskDetections — typically indicates the tenant "
                "does not have Azure AD Premium P2 (required for risk detection data)."
            )
            return {
                "available": False,
                "detectedInPast90Days": 0,
                "sample": [],
                "note": (
                    "/identity/riskDetections returned 400 — typically indicates "
                    "the tenant does not have Azure AD Premium P2. Upgrade licensing "
                    "or collect sign-in risks via the Entra portal."
                ),
            }
        filtered = [
            entry for entry in raw
            if (entry.get("riskLevel") or "").lower() in {"high", "medium"}
        ]
        filtered.sort(key=lambda e: e.get("detectedDateTime") or "", reverse=True)
        sample = [
            {
                "detectedDateTime": entry.get("detectedDateTime"),
                "riskLevel": entry.get("riskLevel"),
                "riskType": entry.get("riskEventType"),
                "userPrincipalName": entry.get("userPrincipalName"),
            }
            for entry in filtered[:25]
        ]
        return {
            "detectedInPast90Days": len(filtered),
            "sample": sample,
        }


def collect(client: GraphClient) -> dict[str, Any]:
    collector = AzureADCollector(client)
    result = collector.collect()
    if collector.warnings:
        result["_collectionWarnings"] = collector.warnings
    return result


def _days_since(iso_timestamp: str | None) -> int | None:
    if not iso_timestamp:
        return None
    try:
        value = iso_timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return max(delta.days, 0)


def _summarize_target(resource: dict[str, Any]) -> str:
    display = resource.get("displayName") or resource.get("type")
    return str(display) if display is not None else ""
