"""One-shot Entra app registration via device-code OAuth.

Run ``python main.py bootstrap --tenant <domain-or-guid>`` to:

1. Open Microsoft's device-login page as an active Global Administrator
   (or Application Administrator + Privileged Role Administrator in PIM).
2. Create the ``cmmc-gcc-evidence-collector`` application in Entra.
3. Mint a client secret with a configurable TTL.
4. Grant admin consent to all 10 required Graph application roles.
5. Write tenant_id and client_id into ``config.json``; print the secret once.

Once this runs successfully, the manual 20-minute Entra portal walkthrough
documented in SETUP.md can be skipped entirely.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)


# Public client ID for Azure CLI — works for device-code auth on commercial,
# GCC, and GCC-High. This means we don't need a pre-existing app to bootstrap.
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# Microsoft Graph service principal's immutable appId.
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

GCC_HIGH_AUTHORITY_BASE = "https://login.microsoftonline.us"
GCC_HIGH_GRAPH_BASE = "https://graph.microsoft.us/v1.0"
GCC_HIGH_GRAPH_ROOT = "https://graph.microsoft.us"

DEFAULT_APP_DISPLAY_NAME = "cmmc-gcc-evidence-collector"
DEFAULT_SECRET_TTL_DAYS = 180

# Application role GUIDs on Microsoft Graph — stable across clouds.
REQUIRED_ROLES: dict[str, str] = {
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
    "Directory.Read.All": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
    "AuditLog.Read.All": "b0afded3-3588-46d8-8b3d-9842eff778da",
    "Policy.Read.All": "246dd0d5-5bd0-4def-940b-0421030a5b68",
    "IdentityRiskEvent.Read.All": "6e472fd1-ad78-48da-a0f0-97ab2c6b769e",
    "DeviceManagementManagedDevices.Read.All": "2f51be20-0bb4-4fed-bf7b-db946066c75e",
    "DeviceManagementConfiguration.Read.All": "dc377aa6-52d8-4e23-b271-2a7ae04cedf3",
    "SecurityEvents.Read.All": "bf394140-e372-4bf9-a898-299cfc7564e5",
    "ThreatIndicators.Read.All": "21792b6c-c986-4ffc-85de-df9da54b52fa",
    "Sites.Read.All": "332a536c-c7ef-4017-ab91-336970924f0d",
}

# Scopes we request during device-code auth — all needed to create and
# consent to the app registration.
BOOTSTRAP_SCOPES = [
    f"{GCC_HIGH_GRAPH_ROOT}/Application.ReadWrite.All",
    f"{GCC_HIGH_GRAPH_ROOT}/AppRoleAssignment.ReadWrite.All",
    f"{GCC_HIGH_GRAPH_ROOT}/Directory.ReadWrite.All",
]


class BootstrapError(RuntimeError):
    """Raised when any bootstrap step fails."""


def bootstrap_app(
    tenant_identifier: str,
    app_display_name: str = DEFAULT_APP_DISPLAY_NAME,
    secret_ttl_days: int = DEFAULT_SECRET_TTL_DAYS,
    msal_module: Any = None,
    requests_module: Any = None,
    print_fn=print,
) -> dict[str, str]:
    """Run the full bootstrap. Returns {tenant_id, client_id, client_secret}.

    ``msal_module`` and ``requests_module`` are injection points for tests;
    production callers should leave them as None.
    """
    msal = msal_module or _import_msal()
    http = requests_module or requests

    # 1. Device-code auth.
    authority = f"{GCC_HIGH_AUTHORITY_BASE}/{tenant_identifier}"
    app = msal.PublicClientApplication(client_id=AZURE_CLI_CLIENT_ID, authority=authority)
    flow = app.initiate_device_flow(scopes=BOOTSTRAP_SCOPES)
    if "user_code" not in flow:
        raise BootstrapError(f"Failed to initiate device flow: {flow}")
    print_fn(flow["message"])
    token_result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in token_result:
        raise BootstrapError(
            f"Device flow did not return a token: {token_result.get('error_description', token_result)}"
        )
    access_token = token_result["access_token"]
    tenant_id = (token_result.get("id_token_claims") or {}).get("tid") or tenant_identifier
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # 2. Confirm the app doesn't already exist.
    existing = _list_apps_by_name(http, headers, app_display_name)
    if existing:
        raise BootstrapError(
            f"App '{app_display_name}' already exists (objectId={existing[0]['id']}). "
            "Delete or rename the existing registration and re-run bootstrap."
        )

    # 3. Look up Microsoft Graph's service principal object id.
    graph_sp_id = _lookup_graph_service_principal(http, headers)

    # 4. Create the application with requiredResourceAccess pre-populated.
    app_obj = _create_application(http, headers, app_display_name)
    client_id = app_obj["appId"]
    app_object_id = app_obj["id"]

    # 5. Create the service principal for our new app.
    new_sp_id = _create_service_principal(http, headers, client_id)

    # 6. Mint a client secret.
    client_secret = _mint_client_secret(http, headers, app_object_id, secret_ttl_days)

    # 7. Grant admin consent by creating appRoleAssignments on Graph's SP.
    _grant_admin_consent(http, headers, graph_sp_id, new_sp_id)

    return {
        "tenant_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }


def _import_msal():
    try:
        import msal  # type: ignore
        return msal
    except ImportError as exc:
        raise BootstrapError(
            "The 'msal' package is required for bootstrap. Run 'pip install msal'."
        ) from exc


def _list_apps_by_name(http, headers, name: str) -> list[dict[str, Any]]:
    r = http.get(
        f"{GCC_HIGH_GRAPH_BASE}/applications",
        headers=headers,
        params={"$filter": f"displayName eq '{name}'", "$select": "id,appId,displayName"},
    )
    _raise_for_graph_error(r, "list applications")
    return (r.json() or {}).get("value") or []


def _lookup_graph_service_principal(http, headers) -> str:
    r = http.get(
        f"{GCC_HIGH_GRAPH_BASE}/servicePrincipals",
        headers=headers,
        params={"$filter": f"appId eq '{GRAPH_APP_ID}'", "$select": "id"},
    )
    _raise_for_graph_error(r, "lookup Graph service principal")
    value = (r.json() or {}).get("value") or []
    if not value:
        raise BootstrapError("Microsoft Graph service principal not found in tenant.")
    return value[0]["id"]


def _create_application(http, headers, display_name: str) -> dict[str, Any]:
    payload = {
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "requiredResourceAccess": [
            {
                "resourceAppId": GRAPH_APP_ID,
                "resourceAccess": [
                    {"id": role_id, "type": "Role"}
                    for role_id in REQUIRED_ROLES.values()
                ],
            }
        ],
    }
    r = http.post(f"{GCC_HIGH_GRAPH_BASE}/applications", headers=headers, json=payload)
    _raise_for_graph_error(r, "create application")
    return r.json()


def _create_service_principal(http, headers, app_id: str) -> str:
    r = http.post(
        f"{GCC_HIGH_GRAPH_BASE}/servicePrincipals",
        headers=headers,
        json={"appId": app_id},
    )
    _raise_for_graph_error(r, "create service principal")
    return r.json()["id"]


def _mint_client_secret(http, headers, app_object_id: str, ttl_days: int) -> str:
    end_dt = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat()
    r = http.post(
        f"{GCC_HIGH_GRAPH_BASE}/applications/{app_object_id}/addPassword",
        headers=headers,
        json={
            "passwordCredential": {
                "displayName": "cmmc-collector bootstrap",
                "endDateTime": end_dt,
            }
        },
    )
    _raise_for_graph_error(r, "mint client secret")
    secret = r.json().get("secretText")
    if not secret:
        raise BootstrapError("Secret was created but Graph did not return its value.")
    return secret


def _grant_admin_consent(http, headers, graph_sp_id: str, new_sp_id: str) -> None:
    for role_name, role_id in REQUIRED_ROLES.items():
        r = http.post(
            f"{GCC_HIGH_GRAPH_BASE}/servicePrincipals/{graph_sp_id}/appRoleAssignedTo",
            headers=headers,
            json={
                "principalId": new_sp_id,
                "resourceId": graph_sp_id,
                "appRoleId": role_id,
            },
        )
        # 201 = created, 400 = already assigned (safe to ignore).
        if r.status_code == 201:
            continue
        if r.status_code == 400:
            body = (r.json() or {}) if _safe_json(r) else {}
            code = ((body.get("error") or {}).get("code") or "").lower()
            if "already" in code or "existingvalue" in code:
                continue
        _raise_for_graph_error(r, f"grant consent for {role_name}")


def _safe_json(r) -> bool:
    try:
        r.json()
        return True
    except Exception:
        return False


def _raise_for_graph_error(response, step: str) -> None:
    if response.status_code < 400:
        return
    body = ""
    try:
        body = response.json()
    except Exception:
        body = response.text
    raise BootstrapError(f"Graph {step} failed ({response.status_code}): {body}")
