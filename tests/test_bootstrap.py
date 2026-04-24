"""Tests for the Entra bootstrap flow using mocked MSAL + Graph."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

import bootstrap


class FakeResponse:
    def __init__(self, status_code: int, body=None, text: str = ""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


def _stub_msal(tenant_id: str = "00000000-0000-0000-0000-000000000000"):
    msal = MagicMock()
    app = MagicMock()
    app.initiate_device_flow.return_value = {
        "user_code": "ABCDEF",
        "message": "Enter code ABCDEF at microsoft.com/devicelogin",
    }
    app.acquire_token_by_device_flow.return_value = {
        "access_token": "fake-token",
        "id_token_claims": {"tid": tenant_id},
    }
    msal.PublicClientApplication.return_value = app
    return msal


def _happy_http():
    """Stub HTTP client that satisfies the full bootstrap happy path."""
    http = MagicMock()

    def get(url, headers=None, params=None):
        if "/applications" in url and params and params.get("$filter", "").startswith("displayName"):
            return FakeResponse(200, {"value": []})
        if "/servicePrincipals" in url and params and params.get("$filter", "").startswith("appId"):
            return FakeResponse(200, {"value": [{"id": "graph-sp-id"}]})
        return FakeResponse(200, {"value": []})

    posts = []
    def post(url, headers=None, json=None):
        posts.append((url, json))
        if url.endswith("/applications"):
            return FakeResponse(201, {"appId": "new-client-id", "id": "app-object-id"})
        if url.endswith("/servicePrincipals"):
            return FakeResponse(201, {"id": "new-sp-id"})
        if "/addPassword" in url:
            return FakeResponse(200, {"secretText": "super-secret-value"})
        if "/appRoleAssignedTo" in url:
            return FakeResponse(201, {})
        return FakeResponse(200, {})

    http.get.side_effect = get
    http.post.side_effect = post
    http._posts = posts
    return http


def test_bootstrap_happy_path_creates_app_and_returns_secret():
    msal = _stub_msal()
    http = _happy_http()
    result = bootstrap.bootstrap_app(
        tenant_identifier="contoso.onmicrosoft.us",
        msal_module=msal,
        requests_module=http,
        print_fn=lambda *a, **k: None,
    )
    assert result["tenant_id"] == "00000000-0000-0000-0000-000000000000"
    assert result["client_id"] == "new-client-id"
    assert result["client_secret"] == "super-secret-value"


def test_bootstrap_consents_to_all_ten_roles():
    msal = _stub_msal()
    http = _happy_http()
    bootstrap.bootstrap_app(
        tenant_identifier="contoso.onmicrosoft.us",
        msal_module=msal,
        requests_module=http,
        print_fn=lambda *a, **k: None,
    )
    role_grants = [p for p in http._posts if "/appRoleAssignedTo" in p[0]]
    assert len(role_grants) == len(bootstrap.REQUIRED_ROLES)
    granted_ids = {p[1]["appRoleId"] for p in role_grants}
    assert granted_ids == set(bootstrap.REQUIRED_ROLES.values())


def test_bootstrap_fails_when_app_already_exists():
    msal = _stub_msal()
    http = MagicMock()
    http.get.side_effect = lambda url, **kw: FakeResponse(
        200,
        {"value": [{"id": "existing-id", "displayName": "cmmc-gcc-evidence-collector"}]}
        if "/applications" in url and "displayName" in (kw.get("params") or {}).get("$filter", "")
        else {"value": [{"id": "graph-sp-id"}]},
    )
    with pytest.raises(bootstrap.BootstrapError, match="already exists"):
        bootstrap.bootstrap_app(
            tenant_identifier="contoso.onmicrosoft.us",
            msal_module=msal,
            requests_module=http,
            print_fn=lambda *a, **k: None,
        )


def test_bootstrap_surfaces_device_flow_token_failure():
    msal = MagicMock()
    app = MagicMock()
    app.initiate_device_flow.return_value = {"user_code": "X", "message": "go"}
    app.acquire_token_by_device_flow.return_value = {
        "error": "authorization_declined",
        "error_description": "User declined",
    }
    msal.PublicClientApplication.return_value = app
    with pytest.raises(bootstrap.BootstrapError, match="Device flow"):
        bootstrap.bootstrap_app(
            tenant_identifier="x",
            msal_module=msal,
            requests_module=MagicMock(),
            print_fn=lambda *a, **k: None,
        )


def test_bootstrap_tolerates_already_granted_role():
    msal = _stub_msal()
    http = MagicMock()

    def get(url, headers=None, params=None):
        if "/applications" in url and params and params.get("$filter", "").startswith("displayName"):
            return FakeResponse(200, {"value": []})
        return FakeResponse(200, {"value": [{"id": "graph-sp-id"}]})

    def post(url, headers=None, json=None):
        if url.endswith("/applications"):
            return FakeResponse(201, {"appId": "new-id", "id": "app-id"})
        if url.endswith("/servicePrincipals"):
            return FakeResponse(201, {"id": "new-sp"})
        if "/addPassword" in url:
            return FakeResponse(200, {"secretText": "sec"})
        if "/appRoleAssignedTo" in url:
            # Graph returns 400 with 'existingvalue' when the role's already granted.
            return FakeResponse(400, {"error": {"code": "existingValueError", "message": "already"}})
        return FakeResponse(200, {})

    http.get.side_effect = get
    http.post.side_effect = post
    result = bootstrap.bootstrap_app(
        tenant_identifier="x",
        msal_module=msal,
        requests_module=http,
        print_fn=lambda *a, **k: None,
    )
    # Should still succeed.
    assert result["client_id"] == "new-id"
