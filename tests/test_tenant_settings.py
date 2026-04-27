"""Tests for the tenant_settings collector."""

from __future__ import annotations

from collectors import tenant_settings


class FakeClient:
    def __init__(self, routes=None, paginated=None):
        self.routes = routes or {}
        self.paginated = paginated or {}

    def get(self, path, params=None):
        return self.routes.get(path, {})

    def get_all(self, path, params=None):
        return self.paginated.get(path, [])


def test_tenant_settings_happy_path():
    routes = {
        "/policies/identitySecurityDefaultsEnforcementPolicy": {
            "isEnabled": False,
            "displayName": "Security Defaults",
        },
        "/policies/authorizationPolicy": {
            "defaultUserRolePermissions": {
                "allowedToCreateApps": True,
                "allowedToCreateSecurityGroups": True,
                "allowedToCreateTenants": False,
                "allowedToReadOtherUsers": True,
            },
            "allowInvitesFrom": "everyone",
        },
        "/policies/authenticationMethodsPolicy": {
            "policyVersion": "1.0",
            "authenticationMethodConfigurations": [
                {"id": "fido2", "state": "enabled"},
                {"id": "microsoftAuthenticator", "state": "enabled"},
                {"id": "sms", "state": "disabled"},
            ],
        },
    }
    paginated = {
        "/identity/conditionalAccess/namedLocations": [
            {
                "id": "loc-1",
                "displayName": "Office HQ",
                "@odata.type": "#microsoft.graph.ipNamedLocation",
                "isTrusted": True,
                "ipRanges": [{"cidrAddress": "203.0.113.0/24"}],
            },
        ],
        "/groupSettings": [],
    }
    client = FakeClient(routes=routes, paginated=paginated)
    result = tenant_settings.collect(client)
    assert result["securityDefaults"]["isEnabled"] is False
    assert result["authorizationPolicy"]["allowedToCreateApps"] is True
    assert result["authorizationPolicy"]["allowedToCreateTenants"] is False
    assert len(result["namedLocations"]) == 1
    assert result["namedLocations"][0]["isTrusted"] is True
    assert result["namedLocations"][0]["ipRanges"] == ["203.0.113.0/24"]
    assert any(m["method"] == "fido2" for m in result["authenticationMethodsPolicy"]["methods"])


def test_tenant_settings_handles_empty_responses():
    client = FakeClient()
    result = tenant_settings.collect(client)
    assert result["securityDefaults"]["isEnabled"] is None
    assert result["namedLocations"] == []
    assert result["groupSettings"] == []
