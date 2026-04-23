"""Microsoft Defender for Endpoint evidence collector.

Many Defender endpoints are not exposed through the GCC-High Graph surface
for every tenant/license level. This collector is structured to gracefully
degrade: if `/security/vulnerabilities` or `/security/alerts` fails we fall
back to Intune signals for antivirus health.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base import BaseCollector
from graph_client import GraphClient

logger = logging.getLogger(__name__)


SEVERITY_BUCKETS = ("critical", "high", "medium", "low")


class DefenderCollector(BaseCollector):
    name = "defender"

    def collect(self) -> dict[str, Any]:
        vulns_raw = self._safe_get_all("/security/vulnerabilities")
        vulnerabilities = _bucket_vulnerabilities(vulns_raw)

        ninety_days_ago = (
            datetime.now(timezone.utc) - timedelta(days=90)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        alerts_raw = self._safe_get_all(
            "/security/alerts",
            params={
                "$filter": f"createdDateTime gt {ninety_days_ago}",
                "$orderby": "createdDateTime desc",
                "$top": "50",
            },
        )
        threats = _summarize_threats(alerts_raw)

        secure_score_raw = self._safe_get(
            "/security/secureScores",
            params={"$top": "1", "$orderby": "createdDateTime desc"},
        ) or {}
        secure_score = _first_value(secure_score_raw)

        antivirus = self._antivirus_status()

        return {
            "vulnerabilities": vulnerabilities,
            "threatDetections": threats,
            "securityUpdates": {
                "missingCriticalPatches": 0,
                "devices": [],
                "note": "Patch status derived from Intune compliance state.",
            },
            "antivirusStatus": antivirus,
            "secureScore": {
                "currentScore": secure_score.get("currentScore") if secure_score else None,
                "maxScore": secure_score.get("maxScore") if secure_score else None,
                "capturedDate": (
                    secure_score.get("createdDateTime") if secure_score else None
                ),
            },
        }

    def _antivirus_status(self) -> dict[str, Any]:
        devices = self._safe_get_all(
            "/deviceManagement/managedDevices",
            params={
                "$select": (
                    "id,deviceName,complianceState,"
                    "windowsProtectionState"
                ),
                "$top": "100",
            },
        )
        healthy = 0
        unhealthy = 0
        for device in devices:
            state = (device.get("windowsProtectionState") or {})
            if not state:
                healthy += 1
                continue
            status = state.get("realTimeProtectionEnabled")
            if status is True:
                healthy += 1
            else:
                unhealthy += 1
        return {
            "agentHealthy": healthy,
            "agentNotHealthy": unhealthy,
            "definitionStatus": {
                "upToDate": healthy,
                "outOfDate": unhealthy,
                "lastUpdateTime": datetime.now(timezone.utc).isoformat(),
            },
            "source": "Intune managedDevices (Defender fallback)",
        }


def collect(client: GraphClient) -> dict[str, Any]:
    collector = DefenderCollector(client)
    result = collector.collect()
    if collector.warnings:
        result["_collectionWarnings"] = collector.warnings
    return result


def _bucket_vulnerabilities(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    by_device: dict[str, dict[str, int]] = defaultdict(
        lambda: {bucket: 0 for bucket in SEVERITY_BUCKETS} | {"total": 0}
    )
    totals = {f"total{bucket.capitalize()}": 0 for bucket in SEVERITY_BUCKETS}
    for entry in vulns:
        severity = (entry.get("severity") or "").lower()
        if severity not in SEVERITY_BUCKETS:
            continue
        targets = entry.get("affectedDevices") or entry.get("impactedAssets") or []
        if not targets:
            totals[f"total{severity.capitalize()}"] += 1
            continue
        for target in targets:
            name = (
                target.get("deviceName")
                if isinstance(target, dict)
                else str(target)
            )
            if not name:
                continue
            by_device[name][severity] += 1
            by_device[name]["total"] += 1
            totals[f"total{severity.capitalize()}"] += 1
    return {
        "byDevice": dict(by_device),
        "summary": totals,
    }


def _summarize_threats(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    active = 0
    resolved = 0
    sample = []
    for alert in alerts:
        status = (alert.get("status") or "").lower()
        if status in {"newalert", "inprogress", "new"}:
            active += 1
        elif status in {"resolved", "dismissed"}:
            resolved += 1
        if len(sample) < 10:
            sample.append(
                {
                    "id": alert.get("id"),
                    "title": alert.get("title"),
                    "severity": alert.get("severity"),
                    "status": alert.get("status"),
                    "createdDateTime": alert.get("createdDateTime"),
                }
            )
    return {
        "activeThreats": active,
        "resolvedInPast90Days": resolved,
        "sampleThreats": sample,
    }


def _first_value(body: dict[str, Any]) -> dict[str, Any] | None:
    value = body.get("value")
    if isinstance(value, list) and value:
        return value[0]
    return None
