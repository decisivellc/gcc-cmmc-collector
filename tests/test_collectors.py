"""Collector unit tests with a mocked GraphClient."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from collectors import azure_ad, defender, exchange, intune


class FakeClient:
    """In-memory Graph client that returns data from a routing table."""

    def __init__(self, routes: dict[str, object], paginated_routes: dict[str, object] | None = None):
        self.routes = routes
        self.paginated_routes = paginated_routes or {}

    def get(self, path: str, params=None):
        value = self._lookup(self.routes, path)
        if isinstance(value, Exception):
            raise value
        return value or {}

    def get_all(self, path: str, params=None):
        value = self._lookup(self.paginated_routes, path)
        if isinstance(value, Exception):
            raise value
        return value or []

    @staticmethod
    def _lookup(table: dict, path: str):
        if path in table:
            return table[path]
        for key, value in table.items():
            if path.startswith(key):
                return value
        return None


# ----- Azure AD ---------------------------------------------------------


def test_azure_ad_happy_path():
    paginated = {
        "/users": [
            {
                "id": "user-1",
                "userPrincipalName": "alice@contoso.onmicrosoft.us",
                "displayName": "Alice",
                "accountEnabled": True,
                "createdDateTime": "2024-01-01T00:00:00Z",
                "signInActivity": {"lastSignInDateTime": "2099-04-20T00:00:00Z"},
            }
        ],
        "/users/user-1/registeredDevices": [{"id": "device-1"}],
        "/directoryRoles": [{"id": "role-1", "displayName": "Global Administrator"}],
        "/directoryRoles/role-1/members": [{"id": "user-1"}],
        "/identity/conditionalAccess/policies": [
            {
                "displayName": "Require MFA",
                "state": "enabled",
                "grantControls": {"builtInControls": ["mfa"]},
                "conditions": {
                    "applications": {"includeApplications": ["All"]},
                    "users": {"includeUsers": ["All"]},
                },
            }
        ],
        "/auditLogs/directoryAudits": [
            {
                "activityDateTime": "2099-04-20T14:30:00Z",
                "operationType": "Update",
                "activityDisplayName": "Update user",
                "result": "success",
                "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.onmicrosoft.us"}},
                "targetResources": [{"displayName": "Bob"}],
            }
        ],
        "/identity/riskDetections": [],
    }
    routes = {"/organization": {"value": [{"id": "org-1"}]}, "/policies/authorizationPolicy": {}}
    client = FakeClient(routes=routes, paginated_routes=paginated)
    evidence = azure_ad.collect(client)
    assert evidence["users"][0]["mfaStatus"] == "enabled"
    assert evidence["users"][0]["assignedRoles"] == ["Global Administrator"]
    assert evidence["conditionalAccessPolicies"][0]["state"] == "enabled"
    assert evidence["auditLogs"]["logsAvailable"] is True


def test_azure_ad_degrades_when_users_call_fails():
    paginated = {"/users": Exception("boom")}
    client = FakeClient(routes={}, paginated_routes=paginated)
    evidence = azure_ad.collect(client)
    assert evidence["users"] == []
    assert evidence["conditionalAccessPolicies"] == []


# ----- Intune -----------------------------------------------------------


def test_intune_filters_macos_and_summarizes():
    paginated = {
        "/deviceManagement/managedDevices": [
            {
                "id": "dev-1",
                "deviceName": "MacBook",
                "operatingSystem": "macOS",
                "osVersion": "14.4.1",
                "deviceEnrollmentType": "macOSEnrollment",
                "enrolledDateTime": "2024-03-01",
                "lastSyncDateTime": "2099-04-20T00:00:00Z",
                "complianceState": "compliant",
                "managementState": "managed",
                "isEncrypted": True,
            }
        ],
        "/deviceManagement/deviceCompliancePolicies": [{"id": "pol-1", "displayName": "Baseline"}],
        "/deviceManagement/deviceCompliancePolicies/pol-1/deviceStatuses": [
            {"status": "compliant"}
        ],
    }
    client = FakeClient(routes={}, paginated_routes=paginated)
    evidence = intune.collect(client)
    assert evidence["deviceComplianceSummary"]["totalDevices"] == 1
    assert evidence["deviceComplianceSummary"]["compliancePercentage"] == 100
    assert evidence["compliancePolicies"][0]["compliantDevices"] == 1


def test_intune_handles_missing_devices():
    client = FakeClient(routes={}, paginated_routes={})
    evidence = intune.collect(client)
    assert evidence["devices"] == []
    assert evidence["deviceComplianceSummary"]["totalDevices"] == 0


# ----- Defender --------------------------------------------------------


def test_defender_collects_alerts_score_and_antivirus():
    paginated = {
        "/security/alerts": [{"id": "a1", "status": "newAlert", "severity": "high"}],
        "/deviceManagement/managedDevices": [
            {"id": "dev-1", "windowsProtectionState": {"realTimeProtectionEnabled": True}}
        ],
    }
    routes = {"/security/secureScores": {"value": [{"currentScore": 600, "maxScore": 800}]}}
    client = FakeClient(routes=routes, paginated_routes=paginated)
    evidence = defender.collect(client)
    assert evidence["vulnerabilities"]["available"] is False
    assert "Defender for Endpoint API" in evidence["vulnerabilities"]["note"]
    assert evidence["threatDetections"]["activeThreats"] == 1
    assert evidence["secureScore"]["currentScore"] == 600
    assert evidence["antivirusStatus"]["agentHealthy"] == 1


def test_defender_gracefully_degrades():
    client = FakeClient(
        routes={"/security/secureScores": Exception("no access")},
        paginated_routes={},
    )
    evidence = defender.collect(client)
    assert evidence["vulnerabilities"]["summary"]["totalHigh"] == 0
    assert evidence["secureScore"]["currentScore"] is None


# ----- Exchange -------------------------------------------------------


def test_exchange_fallback_message_when_no_audit():
    client = FakeClient(routes={}, paginated_routes={"/users": [{"id": "u1", "displayName": "A", "userPrincipalName": "a@contoso.onmicrosoft.us", "mail": "a@contoso.onmicrosoft.us"}]})
    evidence = exchange.collect(client)
    assert evidence["exchangeAuditLog"]["logsAvailable"] is False
    assert "reason" in evidence["exchangeAuditLog"]
    assert evidence["mailboxes"][0]["primarySmtpAddress"] == "a@contoso.onmicrosoft.us"


def test_exchange_uses_graph_audit_when_available():
    paginated = {
        "/users": [],
        "/auditLogs/directoryAudits": [
            {
                "activityDateTime": "2099-04-20T00:00:00Z",
                "activityDisplayName": "Mailbox update",
                "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.onmicrosoft.us"}},
                "result": "success",
            },
            {
                "activityDateTime": "2099-04-19T00:00:00Z",
                "activityDisplayName": "Mailbox update",
                "initiatedBy": {"user": {"userPrincipalName": "ops@contoso.onmicrosoft.us"}},
                "result": "success",
            },
        ],
    }
    client = FakeClient(routes={}, paginated_routes=paginated)
    evidence = exchange.collect(client)
    audit = evidence["exchangeAuditLog"]
    assert audit["logsAvailable"] is True
    assert audit["eventCount"] == 2
    assert audit["uniqueInitiators"] == 2
    assert audit["topOperations"][0]["operation"] == "Mailbox update"
    assert audit["topOperations"][0]["count"] == 2
    assert "Purview" in audit["scope"]
    assert evidence["dlpPolicies"]["available"] is False
    assert "Security & Compliance PowerShell" in evidence["dlpPolicies"]["note"]


def test_exchange_mailboxes_no_longer_carry_hardcoded_audit_flag():
    paginated = {
        "/users": [
            {"id": "u1", "displayName": "Alice", "userPrincipalName": "a@contoso.onmicrosoft.us", "mail": "a@contoso.onmicrosoft.us"}
        ],
    }
    client = FakeClient(routes={}, paginated_routes=paginated)
    evidence = exchange.collect(client)
    mailbox = evidence["mailboxes"][0]
    assert mailbox["primarySmtpAddress"] == "a@contoso.onmicrosoft.us"
    assert "auditEnabled" not in mailbox
    assert "auditLog" not in mailbox
