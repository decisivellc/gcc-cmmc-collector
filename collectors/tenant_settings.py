"""Tenant-wide policy and settings collector.

Pulls settings that aren't tied to a specific user, device, or app but
still drive the security posture: security defaults state, default user
role permissions, named locations, authentication methods policy, group
settings.

No new Graph permissions required beyond Policy.Read.All and
Directory.Read.All which the tool already holds.
"""

from __future__ import annotations

import logging
from typing import Any

from collectors.base import BaseCollector
from graph_client import GraphClient

logger = logging.getLogger(__name__)


class TenantSettingsCollector(BaseCollector):
    name = "tenant_settings"

    def collect(self) -> dict[str, Any]:
        return {
            "securityDefaults": self._collect_security_defaults(),
            "authorizationPolicy": self._collect_authorization_policy(),
            "namedLocations": self._collect_named_locations(),
            "authenticationMethodsPolicy": self._collect_auth_methods_policy(),
            "groupSettings": self._collect_group_settings(),
        }

    def _collect_security_defaults(self) -> dict[str, Any]:
        body = self._safe_get("/policies/identitySecurityDefaultsEnforcementPolicy") or {}
        return {
            "isEnabled": body.get("isEnabled"),
            "displayName": body.get("displayName"),
            "description": body.get("description"),
        }

    def _collect_authorization_policy(self) -> dict[str, Any]:
        body = self._safe_get("/policies/authorizationPolicy") or {}
        permissions = body.get("defaultUserRolePermissions") or {}
        return {
            "allowedToCreateApps": permissions.get("allowedToCreateApps"),
            "allowedToCreateSecurityGroups": permissions.get("allowedToCreateSecurityGroups"),
            "allowedToCreateTenants": permissions.get("allowedToCreateTenants"),
            "allowedToReadBitlockerKeysForOwnedDevice": permissions.get(
                "allowedToReadBitlockerKeysForOwnedDevice"
            ),
            "allowedToReadOtherUsers": permissions.get("allowedToReadOtherUsers"),
            "allowedToSignUpEmailBasedSubscriptions": permissions.get(
                "allowedToSignUpEmailBasedSubscriptions"
            ),
            "allowEmailVerifiedUsersToJoinOrganization": body.get(
                "allowEmailVerifiedUsersToJoinOrganization"
            ),
            "allowInvitesFrom": body.get("allowInvitesFrom"),
            "blockMsolPowerShell": body.get("blockMsolPowerShell"),
            "permissionGrantPoliciesAssigned": permissions.get(
                "permissionGrantPoliciesAssigned"
            ) or [],
        }

    def _collect_named_locations(self) -> list[dict[str, Any]]:
        raw = self._safe_get_all("/identity/conditionalAccess/namedLocations")
        locations: list[dict[str, Any]] = []
        for entry in raw:
            kind = entry.get("@odata.type", "").split(".")[-1]
            locations.append(
                {
                    "id": entry.get("id"),
                    "displayName": entry.get("displayName"),
                    "type": kind,  # ipNamedLocation or countryNamedLocation
                    "isTrusted": entry.get("isTrusted"),
                    "ipRanges": [r.get("cidrAddress") for r in entry.get("ipRanges") or []],
                    "countriesAndRegions": entry.get("countriesAndRegions") or [],
                }
            )
        return locations

    def _collect_auth_methods_policy(self) -> dict[str, Any]:
        body = self._safe_get("/policies/authenticationMethodsPolicy") or {}
        configurations = body.get("authenticationMethodConfigurations") or []
        methods = []
        for cfg in configurations:
            methods.append(
                {
                    "method": cfg.get("id"),
                    "state": cfg.get("state"),
                }
            )
        return {
            "policyVersion": body.get("policyVersion"),
            "registrationEnforcement": body.get("registrationEnforcement"),
            "methods": methods,
        }

    def _collect_group_settings(self) -> list[dict[str, Any]]:
        raw = self._safe_get_all("/groupSettings")
        settings: list[dict[str, Any]] = []
        for entry in raw:
            values = {v["name"]: v["value"] for v in entry.get("values") or [] if v.get("name")}
            settings.append(
                {
                    "displayName": entry.get("displayName"),
                    "templateId": entry.get("templateId"),
                    "values": values,
                }
            )
        return settings


def collect(client: GraphClient) -> dict[str, Any]:
    collector = TenantSettingsCollector(client)
    result = collector.collect()
    if collector.warnings:
        result["_collectionWarnings"] = collector.warnings
    return result
