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

    def __init__(self, client: GraphClient, os_filter: str | None = None) -> None:
        super().__init__(client)
        # Empty string or explicit None means "all operating systems".
        self.os_filter = os_filter or None

    def collect(self) -> dict[str, Any]:
        devices = self._collect_devices()
        policies = self._collect_compliance_policies()
        summary = _summarize_devices(devices)
        per_os = _summarize_by_os(devices)
        return {
            "devices": devices,
            "compliancePolicies": policies,
            "deviceComplianceSummary": summary,
            "deviceComplianceByOs": per_os,
            "osFilter": self.os_filter,
        }

    def _collect_devices(self) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"$top": "100"}
        if self.os_filter:
            params["$filter"] = f"operatingSystem eq '{self.os_filter}'"
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


def collect(client: GraphClient, os_filter: str | None = None) -> dict[str, Any]:
    collector = IntuneCollector(client, os_filter=os_filter)
    result = collector.collect()
    if collector.warnings:
        result["_collectionWarnings"] = collector.warnings
    return result


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


def _summarize_by_os(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group devices by operatingSystem and return a per-OS compliance row."""
    buckets: dict[str, dict[str, Any]] = {}
    for d in devices:
        key = d.get("operatingSystem") or "unknown"
        bucket = buckets.setdefault(key, {"operatingSystem": key, "total": 0, "compliant": 0})
        bucket["total"] += 1
        if d.get("complianceState") == "compliant":
            bucket["compliant"] += 1
    rows: list[dict[str, Any]] = []
    for bucket in buckets.values():
        pct = round((bucket["compliant"] / bucket["total"]) * 100) if bucket["total"] else 0
        rows.append({**bucket, "compliancePercentage": pct})
    rows.sort(key=lambda r: r["operatingSystem"].casefold())
    return rows


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
