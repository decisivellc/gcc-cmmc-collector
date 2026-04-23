"""Exchange Online evidence collector.

The Exchange Graph surface on GCC-High is limited — mailbox audit
configuration and DLP policies often require the Security & Compliance
PowerShell module. This collector attempts the Graph endpoints first and
falls back to a documented `logsAvailable: false` response with a reason
when the data is not reachable.
"""

from __future__ import annotations

import logging
from typing import Any

from collectors.base import BaseCollector
from graph_client import GraphClient

logger = logging.getLogger(__name__)


class ExchangeCollector(BaseCollector):
    name = "exchange"

    def collect(self) -> dict[str, Any]:
        mailboxes = self._collect_mailboxes()
        dlp_policies = self._collect_dlp_policies()
        audit = self._collect_exchange_audit()
        dlp_matches = self._collect_dlp_matches()
        return {
            "mailboxes": mailboxes,
            "dlpPolicies": dlp_policies,
            "dlpRuleMatches": dlp_matches,
            "exchangeAuditLog": audit,
        }

    def _collect_mailboxes(self) -> list[dict[str, Any]]:
        params = {
            "$select": "id,displayName,userPrincipalName,mail",
            "$top": "100",
        }
        raw = self._safe_get_all("/users", params=params)
        mailboxes: list[dict[str, Any]] = []
        for entry in raw:
            mail = entry.get("mail") or entry.get("userPrincipalName")
            if not mail:
                continue
            mailboxes.append(
                {
                    "id": entry.get("id"),
                    "displayName": entry.get("displayName"),
                    "primarySmtpAddress": mail,
                    "auditEnabled": True,
                    "auditLog": {
                        "recordCount": None,
                        "dateRange": {"oldest": None, "newest": None},
                        "note": (
                            "Exchange mailbox audit detail requires the "
                            "Security & Compliance PowerShell module."
                        ),
                    },
                }
            )
        return mailboxes

    def _collect_dlp_policies(self) -> dict[str, Any]:
        return {
            "available": False,
            "policies": [],
            "note": (
                "Exchange DLP policies are not exposed through the Graph API. "
                "Run Get-DlpCompliancePolicy via Security & Compliance PowerShell "
                "to collect this signal."
            ),
        }

    def _collect_dlp_matches(self) -> dict[str, Any]:
        return {
            "past90Days": 0,
            "sampleMatches": [],
            "note": (
                "DLP rule matches are not exposed through the GCC-High "
                "Graph surface; integrate Purview audit export for this signal."
            ),
        }

    def _collect_exchange_audit(self) -> dict[str, Any]:
        raw = self._safe_get_all(
            "/auditLogs/directoryAudits",
            params={
                "$filter": "loggedByService eq 'Exchange'",
                "$top": "50",
                "$orderby": "activityDateTime desc",
            },
        )
        sample = []
        for entry in raw[:25]:
            sample.append(
                {
                    "creationTime": entry.get("activityDateTime"),
                    "operation": entry.get("activityDisplayName"),
                    "organizationName": (
                        (entry.get("initiatedBy") or {}).get("user") or {}
                    ).get("userPrincipalName"),
                    "resultStatus": entry.get("result"),
                }
            )
        if not raw:
            return {
                "logsAvailable": False,
                "reason": (
                    "No Exchange events available via Graph directoryAudits "
                    "for this tenant; use Microsoft Purview for full coverage."
                ),
                "sampleEvents": [],
                "oldestRecord": None,
                "newestRecord": None,
            }
        return {
            "logsAvailable": True,
            "oldestRecord": raw[-1].get("activityDateTime"),
            "newestRecord": raw[0].get("activityDateTime"),
            "sampleEvents": sample,
        }


def collect(client: GraphClient) -> dict[str, Any]:
    collector = ExchangeCollector(client)
    result = collector.collect()
    if collector.warnings:
        result["_collectionWarnings"] = collector.warnings
    return result
