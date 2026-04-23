"""Tests for the thin Graph client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from graph_client import (
    DEFAULT_GRAPH_BASE_URL,
    GraphAuthError,
    GraphClient,
    _scope_from_base,
)


def _make_response(status: int = 200, body: dict | None = None, headers: dict | None = None) -> MagicMock:
    response = MagicMock(spec=requests.Response)
    response.status_code = status
    response.content = b"{}" if body is None else b"payload"
    response.json.return_value = body or {}
    response.headers = headers or {}
    response.raise_for_status.side_effect = None
    return response


def _make_client(session: MagicMock | None = None, token: str = "test-token") -> GraphClient:
    with patch("graph_client.msal.ConfidentialClientApplication") as mock_app:
        instance = MagicMock()
        instance.acquire_token_for_client.return_value = {"access_token": token}
        mock_app.return_value = instance
        client = GraphClient(
            tenant_id="tenant",
            client_id="client",
            client_secret="secret",
            session=session or MagicMock(spec=requests.Session),
        )
    return client


def test_scope_derived_from_base_url():
    assert _scope_from_base("https://graph.microsoft.us/v1.0") == "https://graph.microsoft.us/.default"
    assert _scope_from_base("https://graph.microsoft.us") == "https://graph.microsoft.us/.default"


def test_constructor_validates_required_fields():
    with pytest.raises(ValueError):
        GraphClient(tenant_id="", client_id="x", client_secret="y")


def test_authority_uses_us_gov_cloud():
    with patch("graph_client.msal.ConfidentialClientApplication") as mock_app:
        mock_app.return_value = MagicMock(
            acquire_token_for_client=MagicMock(return_value={"access_token": "t"})
        )
        GraphClient(tenant_id="tenant123", client_id="c", client_secret="s")
        call_kwargs = mock_app.call_args.kwargs
        assert call_kwargs["authority"] == "https://login.microsoftonline.us/tenant123"


def test_raises_on_token_failure():
    with patch("graph_client.msal.ConfidentialClientApplication") as mock_app:
        mock_app.return_value = MagicMock(
            acquire_token_for_client=MagicMock(
                return_value={"error_description": "bad creds"}
            )
        )
        client = GraphClient(tenant_id="t", client_id="c", client_secret="s")
        with pytest.raises(GraphAuthError):
            client.get("/users")


def test_get_all_follows_next_link():
    session = MagicMock(spec=requests.Session)
    page_one = _make_response(
        body={
            "value": [{"id": "1"}],
            "@odata.nextLink": f"{DEFAULT_GRAPH_BASE_URL}/users?$skiptoken=abc",
        }
    )
    page_two = _make_response(body={"value": [{"id": "2"}]})
    session.request.side_effect = [page_one, page_two]

    client = _make_client(session=session)
    items = client.get_all("/users")
    assert [item["id"] for item in items] == ["1", "2"]
    assert session.request.call_count == 2


def test_retries_on_429_once():
    session = MagicMock(spec=requests.Session)
    throttled = _make_response(status=429, headers={"Retry-After": "0"})
    ok = _make_response(body={"value": []})
    session.request.side_effect = [throttled, ok]
    client = _make_client(session=session)
    client.get_all("/users")
    assert session.request.call_count == 2


def test_re_authenticates_on_401():
    session = MagicMock(spec=requests.Session)
    unauth = _make_response(status=401)
    ok = _make_response(body={"value": [{"id": "1"}]})
    session.request.side_effect = [unauth, ok]
    client = _make_client(session=session)
    items = client.get_all("/users")
    assert [item["id"] for item in items] == ["1"]
    assert client._cached_token == "test-token"
