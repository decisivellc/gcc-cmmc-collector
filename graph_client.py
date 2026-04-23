"""Thin Graph API client for the GCC-High sovereign cloud.

Uses MSAL for client-credentials auth against the US-Gov authority
(`login.microsoftonline.us`) and `requests` for calls against
`graph.microsoft.us`.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Iterable

import msal
import requests

logger = logging.getLogger(__name__)


DEFAULT_AUTHORITY = "https://login.microsoftonline.us"
DEFAULT_GRAPH_BASE_URL = "https://graph.microsoft.us/v1.0"
DEFAULT_SCOPE = "https://graph.microsoft.us/.default"
REQUEST_TIMEOUT_SECONDS = 30


class GraphAuthError(RuntimeError):
    """Raised when MSAL fails to return an access token."""


class GraphClient:
    """Authenticated Graph client for a single GCC-High tenant."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        authority: str = DEFAULT_AUTHORITY,
        graph_base_url: str = DEFAULT_GRAPH_BASE_URL,
        session: requests.Session | None = None,
    ) -> None:
        if not tenant_id or not client_id or not client_secret:
            raise ValueError("tenant_id, client_id, and client_secret are required")

        self.tenant_id = tenant_id
        self.client_id = client_id
        self.graph_base_url = graph_base_url.rstrip("/")
        self._scope = [_scope_from_base(graph_base_url)]
        self._session = session or requests.Session()
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"{authority.rstrip('/')}/{tenant_id}",
        )
        self._cached_token: str | None = None

    def _acquire_token(self) -> str:
        if self._cached_token:
            return self._cached_token
        result = self._app.acquire_token_for_client(scopes=self._scope)
        if not isinstance(result, dict) or "access_token" not in result:
            raise GraphAuthError(
                f"Failed to acquire Graph token: {result.get('error_description') if isinstance(result, dict) else result}"
            )
        self._cached_token = result["access_token"]
        return self._cached_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._acquire_token()}",
            "Accept": "application/json",
        }

    def _full_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return f"{self.graph_base_url}{path_or_url}"

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET a single Graph resource and return the parsed JSON body."""
        url = self._full_url(path)
        response = self._request_with_retry("GET", url, params=params)
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()

    def get_all(
        self, path: str, params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """GET a Graph collection, following `@odata.nextLink` pagination."""
        url: str | None = self._full_url(path)
        first = True
        items: list[dict[str, Any]] = []
        while url:
            response = self._request_with_retry(
                "GET", url, params=params if first else None
            )
            first = False
            if not response.content:
                break
            body = response.json()
            value = body.get("value")
            if isinstance(value, list):
                items.extend(value)
            else:
                items.append(body)
                break
            url = body.get("@odata.nextLink")
        return items

    def _request_with_retry(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
    ) -> requests.Response:
        last_exception: Exception | None = None
        for attempt in range(2):
            try:
                response = self._session.request(
                    method,
                    url,
                    headers=self._headers(),
                    params=params,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
            except requests.RequestException as exc:
                last_exception = exc
                if attempt == 0:
                    logger.warning("Graph request error on %s, retrying: %s", url, exc)
                    time.sleep(1)
                    continue
                raise

            if response.status_code == 401 and attempt == 0:
                self._cached_token = None
                continue

            if response.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                delay = _retry_delay(response)
                logger.warning(
                    "Graph request %s returned %s, retrying in %ss",
                    url,
                    response.status_code,
                    delay,
                )
                time.sleep(delay)
                continue

            if response.status_code >= 400:
                response.raise_for_status()
            return response

        if last_exception is not None:
            raise last_exception
        raise RuntimeError(f"Exhausted retries for {url}")


def _retry_delay(response: requests.Response) -> float:
    header = response.headers.get("Retry-After")
    if header:
        try:
            return float(header)
        except ValueError:
            pass
    return 2.0


def _scope_from_base(graph_base_url: str) -> str:
    """Derive the .default scope from the Graph base URL."""
    base = graph_base_url.rstrip("/")
    if base.endswith("/v1.0") or base.endswith("/beta"):
        base = base.rsplit("/", 1)[0]
    return f"{base}/.default"


def _combined_params(
    base: dict[str, Any] | None, extra: Iterable[tuple[str, Any]]
) -> dict[str, Any]:
    params: dict[str, Any] = dict(base or {})
    for key, value in extra:
        params[key] = value
    return params
