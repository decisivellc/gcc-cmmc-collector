"""Shared base class for evidence collectors."""

from __future__ import annotations

import logging
from typing import Any

from graph_client import GraphClient

logger = logging.getLogger(__name__)


class BaseCollector:
    """Abstract base for a single-system evidence collector."""

    name: str = "base"

    def __init__(self, client: GraphClient) -> None:
        self.client = client

    def collect(self) -> dict[str, Any]:
        raise NotImplementedError

    def _safe_get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        default: Any = None,
    ) -> Any:
        """Fetch a single resource, returning ``default`` on error."""
        try:
            return self.client.get(path, params=params)
        except Exception as exc:
            logger.warning("%s: GET %s failed: %s", self.name, path, exc)
            return default

    def _safe_get_all(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch a paginated collection, returning ``[]`` on error."""
        try:
            return self.client.get_all(path, params=params)
        except Exception as exc:
            logger.warning("%s: GET %s (paginated) failed: %s", self.name, path, exc)
            return []
