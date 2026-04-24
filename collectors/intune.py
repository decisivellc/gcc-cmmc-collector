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
        config_profiles = self._collect_configuration_profiles()
        summary = _summarize_devices(devices)
        per_os = _summarize_by_os(devices)
        return {
            "devices": devices,
            "compliancePolicies": policies,
            "configurationProfiles": config_profiles,
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


    def _get_beta_all(self, path: str) -> list[dict[str, Any]]:
        """Hit the beta Graph surface for endpoints that aren't in v1.0 on
        GCC-High (settings-catalog policies and endpoint security intents).
        Falls back to an empty list and records a warning on failure."""
        v1_base = getattr(self.client, "graph_base_url", "")
        if "/v1.0" in v1_base:
            full_url = v1_base.replace("/v1.0", "/beta").rstrip("/") + path
        else:
            # Fake clients in tests or unusual configs: just try the path as-is.
            full_url = path
        try:
            return self.client.get_all(full_url)
        except Exception as exc:
            logger.warning("%s: beta GET %s failed: %s", self.name, path, exc)
            self._record_warning(f"beta:{path}", exc, paginated=True)
            return []

    def _collect_configuration_profiles(self) -> dict[str, Any]:
        """Three Graph surfaces carry configuration baselines for Intune:
        the legacy ``deviceConfigurations`` (v1.0), the settings-catalog
        ``configurationPolicies`` (beta-only in GCC-High), and endpoint
        security ``intents`` (beta-only in GCC-High). We merge them into a
        single list with a ``source`` marker so the report can show where
        each profile came from."""
        legacy = self._safe_get_all("/deviceManagement/deviceConfigurations")
        settings_catalog = self._get_beta_all("/deviceManagement/configurationPolicies")
        intents = self._get_beta_all("/deviceManagement/intents")

        profiles: list[dict[str, Any]] = []
        for entry in legacy:
            profiles.append(_normalize_profile(entry, source="deviceConfiguration"))
        for entry in settings_catalog:
            profiles.append(_normalize_profile(entry, source="configurationPolicy"))
        for entry in intents:
            profiles.append(_normalize_profile(entry, source="endpointSecurityIntent"))

        for profile in profiles:
            if not profile.get("id"):
                continue
            path = _assignments_path(profile["source"], profile["id"])
            if path is None:
                continue
            if profile["source"] == "deviceConfiguration":
                assignments = self._safe_get_all(path)
            else:
                # Settings catalog and endpoint security intents live under /beta on GCC-High.
                assignments = self._get_beta_all(path)
            profile["assignmentCount"] = len(assignments or [])
            profile["assigned"] = profile["assignmentCount"] > 0

        summary = _summarize_config_profiles(profiles)
        return {"items": profiles, "summary": summary}


def _normalize_profile(entry: dict[str, Any], source: str) -> dict[str, Any]:
    platforms = entry.get("platforms") or entry.get("platform") or entry.get("platformSupport")
    if isinstance(platforms, list):
        platform_list = [p for p in platforms if p]
    elif isinstance(platforms, str) and platforms:
        platform_list = [platforms]
    else:
        platform_list = []
    return {
        "id": entry.get("id"),
        "displayName": entry.get("displayName") or entry.get("name"),
        "description": entry.get("description"),
        "platforms": platform_list,
        "source": source,
        "lastModifiedDateTime": entry.get("lastModifiedDateTime"),
        "createdDateTime": entry.get("createdDateTime"),
        "assignmentCount": 0,
        "assigned": False,
    }


def _assignments_path(source: str, profile_id: str) -> str | None:
    if source == "deviceConfiguration":
        return f"/deviceManagement/deviceConfigurations/{profile_id}/assignments"
    if source == "configurationPolicy":
        return f"/deviceManagement/configurationPolicies/{profile_id}/assignments"
    if source == "endpointSecurityIntent":
        return f"/deviceManagement/intents/{profile_id}/assignments"
    return None


def _summarize_config_profiles(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    assigned = [p for p in profiles if p["assigned"]]
    per_platform: dict[str, dict[str, int]] = {}
    for p in assigned:
        for platform in p["platforms"] or ["unspecified"]:
            key = platform.lower()
            bucket = per_platform.setdefault(key, {"platform": platform, "count": 0})
            bucket["count"] += 1
    platform_rows = sorted(per_platform.values(), key=lambda r: r["platform"].lower())
    return {
        "totalProfiles": len(profiles),
        "assignedProfiles": len(assigned),
        "platformsCovered": platform_rows,
    }


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
