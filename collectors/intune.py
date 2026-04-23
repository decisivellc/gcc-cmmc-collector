"""Intune (Microsoft Endpoint Manager) evidence collector."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from collectors.base import BaseCollector
from graph_client import GraphClient

logger = logging.getLogger(__name__)


class IntuneCollector(BaseCollector):
    name = "intune"

    def __init__(self, client: GraphClient, os_filter: str = "macOS") -> None:
        super().__init__(client)
        self.os_filter = os_filter

    def collect(self) -> dict[str, Any]:
        devices = self._collect_devices()
        policies = self._collect_compliance_policies()
        summary = _summarize_devices(devices)
        return {
            "devices": devices,
            "compliancePolicies": policies,
            "deviceComplianceSummary": summary,
        }

    def _collect_devices(self) -> list[dict[str, Any]]:
        params = {
            "$filter": f"operatingSystem eq '{self.os_filter}'",
            "$top": "100",
        }
        raw = self._safe_get_all("/deviceManagement/managedDevices", params=params)
        devices: list[dict[str, Any]] = []
        for entry in raw:
            last_sync = entry.get("lastSyncDateTime")
            encryption_state = entry.get("isEncrypted")
            compliance = entry.get("complianceState") or "unknown"
            devices.append(
                {
                    "id": entry.get("id"),
                    "deviceName": entry.get("deviceName"),
                    "operatingSystem": entry.get("operatingSystem"),
                    "osVersion": entry.get("osVersion"),
                    "enrollmentType": entry.get("deviceEnrollmentType"),
                    "enrollmentDate": entry.get("enrolledDateTime"),
                    "lastSyncDateTime": last_sync,
                    "complianceState": compliance,
                    "managementState": entry.get("managementState"),
                    "encryption": {
                        "encryptionStatus": (
                            "encrypted" if encryption_state else "unknown"
                            if encryption_state is None
                            else "notEncrypted"
                        ),
                        "encryptionReadiness": (
                            "ready" if encryption_state else "unknown"
                        ),
                    },
                    "lastSyncDaysAgo": _days_since(last_sync),
                    "complianceDetails": _compliance_details(entry),
                }
            )
        return devices

    def _collect_compliance_policies(self) -> list[dict[str, Any]]:
        raw = self._safe_get_all("/deviceManagement/deviceCompliancePolicies")
        policies: list[dict[str, Any]] = []
        for entry in raw:
            policy_id = entry.get("id")
            statuses = self._safe_get_all(
                f"/deviceManagement/deviceCompliancePolicies/{policy_id}/deviceStatuses"
            )
            deployed = len(statuses)
            compliant = sum(
                1 for s in statuses if (s.get("status") or "").lower() == "compliant"
            )
            policies.append(
                {
                    "displayName": entry.get("displayName"),
                    "id": policy_id,
                    "deployedToDevices": deployed,
                    "compliantDevices": compliant,
                    "nonCompliantDevices": max(deployed - compliant, 0),
                }
            )
        return policies


def collect(client: GraphClient) -> dict[str, Any]:
    return IntuneCollector(client).collect()


def _compliance_details(entry: dict[str, Any]) -> dict[str, str]:
    def flag(value: Any) -> str:
        return "Yes" if value else "No" if value is False else "Unknown"

    return {
        "osVersion": entry.get("osVersion") or "Unknown",
        "fileVaultEnabled": flag(entry.get("isEncrypted")),
        "passwordRequired": flag(entry.get("passcodeLockGracePeriodInSeconds") is not None),
        "jailBroken": entry.get("jailBroken") or "Unknown",
        "azureADRegistered": flag(entry.get("azureADRegistered")),
    }


def _summarize_devices(devices: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(devices)
    compliant = sum(1 for d in devices if d["complianceState"] == "compliant")
    percentage = round((compliant / total) * 100) if total else 0
    return {
        "totalDevices": total,
        "compliantDevices": compliant,
        "compliancePercentage": percentage,
        "lastAuditDate": datetime.now(timezone.utc).isoformat(),
    }


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
