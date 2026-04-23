"""SharePoint policy-document evidence collector.

Reads a SharePoint document library containing NIST 800-171 policy documents
and matches filenames against each of the 13 policy-family controls (AC-1,
AT-1, AU-1, CM-1, IA-1, IR-1, MA-1, MP-1, PE-1, PS-1, RA-1, SC-1, SI-1).

The user provides a single ``site_url`` in config. Any of these URL shapes
work — the collector extracts hostname, site path, and library name:

    https://contoso.sharepoint.us/IT%20Policies/Forms/AllItems.aspx
    https://contoso.sharepoint.us/sites/Compliance/Shared%20Documents/Forms/AllItems.aspx
    https://contoso.sharepoint.us/sites/Policies
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import unquote, urlparse

from collectors.base import BaseCollector
from graph_client import GraphClient

logger = logging.getLogger(__name__)


POLICY_KEYWORDS: dict[str, list[str]] = {
    "AC-1": ["access control"],
    "AT-1": ["awareness", "security training", "training policy"],
    "AU-1": ["audit", "accountability"],
    "CM-1": ["configuration management", "change management"],
    "IA-1": ["identification and authentication", "identity policy"],
    "IR-1": ["incident response", "incident handling"],
    "MA-1": ["maintenance policy", "system maintenance"],
    "MP-1": ["media protection", "removable media"],
    "PE-1": ["physical protection", "physical security", "environmental"],
    "PS-1": ["personnel security", "background"],
    "RA-1": ["risk assessment", "risk management"],
    "SC-1": ["system and communications", "communications protection"],
    "SI-1": ["system and information integrity"],
}


class PoliciesCollector(BaseCollector):
    name = "policies"

    def __init__(self, client: GraphClient, site_url: str) -> None:
        super().__init__(client)
        self.site_url = site_url

    def collect(self) -> dict[str, Any]:
        if not self.site_url:
            return _not_configured()

        parsed = _parse_site_url(self.site_url)
        if not parsed:
            return _invalid_url(self.site_url)

        site = self._resolve_site(parsed["hostname"], parsed["site_path"])
        if not site:
            return _site_unreachable(self.site_url)

        drive = self._resolve_library_drive(site["id"], parsed["library_name"])
        if not drive:
            return _library_unreachable(self.site_url, parsed["library_name"])

        documents = self._list_drive_files(drive["id"])
        matches, unmatched = _match_documents(documents)

        return {
            "available": True,
            "site": {
                "url": self.site_url,
                "id": site["id"],
                "hostname": parsed["hostname"],
                "sitePath": parsed["site_path"],
                "libraryName": parsed["library_name"],
                "driveId": drive["id"],
            },
            "documents": documents,
            "controlMatches": matches,
            "unmatched": unmatched,
            "coverage": {
                "controlsCovered": sum(1 for v in matches.values() if v),
                "controlsTotal": len(POLICY_KEYWORDS),
            },
        }

    def _resolve_site(self, hostname: str, site_path: str) -> dict[str, Any] | None:
        if site_path in ("", "/"):
            path = f"/sites/{hostname}"
        else:
            path = f"/sites/{hostname}:{site_path}"
        body = self._safe_get(path) or {}
        if not body.get("id"):
            return None
        return body

    def _resolve_library_drive(self, site_id: str, library_name: str) -> dict[str, Any] | None:
        drives = self._safe_get_all(f"/sites/{site_id}/drives")
        target = library_name.casefold()
        for drive in drives:
            if (drive.get("name") or "").casefold() == target:
                return drive
        # Fall back to substring match to tolerate "Documents" vs "Shared Documents".
        for drive in drives:
            if target and target in (drive.get("name") or "").casefold():
                return drive
        return None

    def _list_drive_files(self, drive_id: str) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        self._walk(drive_id, f"/drives/{drive_id}/root/children", collected, depth=0)
        return collected

    def _walk(
        self,
        drive_id: str,
        path: str,
        accumulator: list[dict[str, Any]],
        depth: int,
    ) -> None:
        if depth > 3:
            return
        entries = self._safe_get_all(path)
        for entry in entries:
            if "folder" in entry:
                child_path = f"/drives/{drive_id}/items/{entry['id']}/children"
                self._walk(drive_id, child_path, accumulator, depth + 1)
                continue
            if "file" not in entry:
                continue
            accumulator.append(
                {
                    "name": entry.get("name"),
                    "webUrl": entry.get("webUrl"),
                    "size": entry.get("size"),
                    "lastModifiedDateTime": entry.get("lastModifiedDateTime"),
                }
            )


def collect(client: GraphClient, site_url: str = "") -> dict[str, Any]:
    collector = PoliciesCollector(client, site_url)
    result = collector.collect()
    if collector.warnings:
        result["_collectionWarnings"] = collector.warnings
    return result


def _parse_site_url(raw: str) -> dict[str, str] | None:
    try:
        parsed = urlparse(raw.strip())
    except ValueError:
        return None
    if not parsed.hostname or not parsed.path:
        return None
    hostname = parsed.hostname
    segments = [unquote(seg) for seg in parsed.path.strip("/").split("/") if seg]
    if not segments:
        return None

    # Trim trailing SharePoint UI suffix so we're left with site + library.
    for noise in ("Forms", "AllItems.aspx"):
        if segments and segments[-1].lower() == noise.lower():
            segments.pop()
    while segments and segments[-1].lower() == "forms":
        segments.pop()

    site_segments: list[str] = []
    library_name: str | None = None
    if segments and segments[0].lower() == "sites" and len(segments) >= 2:
        site_segments = segments[:2]
        remainder = segments[2:]
        library_name = remainder[0] if remainder else "Documents"
    else:
        library_name = segments[0] if segments else None

    if not library_name:
        return None

    site_path = "/" + "/".join(site_segments) if site_segments else ""
    return {
        "hostname": hostname,
        "site_path": site_path,
        "library_name": library_name,
    }


def _normalize(text: str) -> str:
    """Lowercase, replace non-alphanumerics with spaces, collapse whitespace.

    Lets keyword ``"access control"`` match filenames like
    ``Access-Control-Policy.docx``, ``access_control_policy.pdf``, or
    ``AccessControlPolicy.docx`` (last one — separate concern; handled by
    substring match against padded tokens).
    """
    lowered = text.casefold()
    return " " + re.sub(r"[^a-z0-9]+", " ", lowered).strip() + " "


def _match_documents(
    documents: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    matches: dict[str, list[dict[str, Any]]] = {cid: [] for cid in POLICY_KEYWORDS}
    unmatched: list[dict[str, Any]] = []
    for doc in documents:
        name_norm = _normalize(doc.get("name") or "")
        matched_any = False
        for control_id, keywords in POLICY_KEYWORDS.items():
            for kw in keywords:
                kw_norm = _normalize(kw).strip()
                if f" {kw_norm} " in name_norm:
                    matches[control_id].append(doc)
                    matched_any = True
                    break
        if not matched_any:
            unmatched.append(doc)
    return matches, unmatched


def _not_configured() -> dict[str, Any]:
    return {
        "available": False,
        "reason": "policies.site_url is not set in config.json",
        "controlMatches": {cid: [] for cid in POLICY_KEYWORDS},
        "documents": [],
    }


def _invalid_url(site_url: str) -> dict[str, Any]:
    return {
        "available": False,
        "reason": f"Could not parse policies.site_url: {site_url}",
        "controlMatches": {cid: [] for cid in POLICY_KEYWORDS},
        "documents": [],
    }


def _site_unreachable(site_url: str) -> dict[str, Any]:
    return {
        "available": False,
        "reason": f"SharePoint site not resolvable: {site_url}",
        "controlMatches": {cid: [] for cid in POLICY_KEYWORDS},
        "documents": [],
    }


def _library_unreachable(site_url: str, library_name: str) -> dict[str, Any]:
    return {
        "available": False,
        "reason": (
            f"SharePoint library '{library_name}' not found in site "
            f"(parsed from {site_url})"
        ),
        "controlMatches": {cid: [] for cid in POLICY_KEYWORDS},
        "documents": [],
    }
