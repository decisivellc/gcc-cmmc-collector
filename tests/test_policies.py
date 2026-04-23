"""Tests for the SharePoint policies collector and mapper integration."""

from __future__ import annotations

import pytest

from collectors import policies
from collectors.policies import _parse_site_url
from mappers import nist_800_171


class FakeClient:
    def __init__(self, routes: dict[str, object], paginated: dict[str, object]):
        self.routes = routes
        self.paginated = paginated

    def get(self, path: str, params=None):
        value = self._lookup(self.routes, path)
        if isinstance(value, Exception):
            raise value
        return value or {}

    def get_all(self, path: str, params=None):
        value = self._lookup(self.paginated, path)
        if isinstance(value, Exception):
            raise value
        return value or []

    @staticmethod
    def _lookup(table, path):
        if path in table:
            return table[path]
        for key, value in table.items():
            if path.startswith(key):
                return value
        return None


@pytest.mark.parametrize(
    "url,expected",
    [
        (
            "https://contoso.sharepoint.us/IT%20Policies/Forms/AllItems.aspx",
            {"hostname": "contoso.sharepoint.us", "site_path": "", "library_name": "IT Policies"},
        ),
        (
            "https://contoso.sharepoint.us/sites/Compliance/Shared%20Documents/Forms/AllItems.aspx",
            {"hostname": "contoso.sharepoint.us", "site_path": "/sites/Compliance", "library_name": "Shared Documents"},
        ),
        (
            "https://contoso.sharepoint.us/sites/Policies",
            {"hostname": "contoso.sharepoint.us", "site_path": "/sites/Policies", "library_name": "Documents"},
        ),
    ],
)
def test_parse_site_url(url, expected):
    assert _parse_site_url(url) == expected


def test_parse_site_url_rejects_garbage():
    assert _parse_site_url("not a url") is None
    assert _parse_site_url("https://no-path.example.us") is None


def test_policies_collector_happy_path():
    routes = {
        "/sites/contoso.sharepoint.us": {"id": "site-1"},
    }
    paginated = {
        "/sites/site-1/drives": [
            {"id": "drive-1", "name": "IT Policies"},
            {"id": "drive-2", "name": "Other"},
        ],
        "/drives/drive-1/root/children": [
            {"id": "f1", "name": "Access Control Policy.pdf", "webUrl": "u1", "file": {}},
            {"id": "f2", "name": "Incident Response Plan.docx", "webUrl": "u2", "file": {}},
            {"id": "f3", "name": "Vendor Checklist.docx", "webUrl": "u3", "file": {}},
        ],
    }
    client = FakeClient(routes=routes, paginated=paginated)
    evidence = policies.collect(
        client,
        "https://contoso.sharepoint.us/IT%20Policies/Forms/AllItems.aspx",
    )
    assert evidence["available"] is True
    assert evidence["site"]["libraryName"] == "IT Policies"
    assert len(evidence["controlMatches"]["AC-1"]) == 1
    assert len(evidence["controlMatches"]["IR-1"]) == 1
    assert len(evidence["controlMatches"]["CM-1"]) == 0
    assert len(evidence["unmatched"]) == 1
    assert evidence["coverage"]["controlsCovered"] == 2
    assert evidence["coverage"]["controlsTotal"] == 13


def test_policies_collector_recurses_into_folders():
    routes = {"/sites/contoso.sharepoint.us": {"id": "site-1"}}
    paginated = {
        "/sites/site-1/drives": [{"id": "drive-1", "name": "IT Policies"}],
        "/drives/drive-1/root/children": [
            {"id": "folder-1", "name": "Archive", "folder": {}},
            {"id": "f1", "name": "Access Control Policy.pdf", "file": {}, "webUrl": "u1"},
        ],
        "/drives/drive-1/items/folder-1/children": [
            {"id": "f2", "name": "Audit and Accountability Policy.pdf", "file": {}, "webUrl": "u2"},
        ],
    }
    client = FakeClient(routes=routes, paginated=paginated)
    evidence = policies.collect(
        client,
        "https://contoso.sharepoint.us/IT%20Policies/Forms/AllItems.aspx",
    )
    assert len(evidence["documents"]) == 2
    assert len(evidence["controlMatches"]["AU-1"]) == 1


def test_policies_collector_not_configured():
    client = FakeClient(routes={}, paginated={})
    evidence = policies.collect(client, "")
    assert evidence["available"] is False
    assert "not set" in evidence["reason"]


def test_policies_collector_site_unreachable():
    routes = {"/sites/contoso.sharepoint.us": {}}
    client = FakeClient(routes=routes, paginated={})
    evidence = policies.collect(
        client,
        "https://contoso.sharepoint.us/IT%20Policies/Forms/AllItems.aspx",
    )
    assert evidence["available"] is False
    assert "not resolvable" in evidence["reason"]


def test_policies_collector_library_not_found():
    routes = {"/sites/contoso.sharepoint.us": {"id": "site-1"}}
    paginated = {
        "/sites/site-1/drives": [{"id": "drive-1", "name": "Something Else"}],
    }
    client = FakeClient(routes=routes, paginated=paginated)
    evidence = policies.collect(
        client,
        "https://contoso.sharepoint.us/IT%20Policies/Forms/AllItems.aspx",
    )
    assert evidence["available"] is False
    assert "not found" in evidence["reason"]


def test_mapper_emits_new_policy_controls(sample_evidence):
    status = nist_800_171.map(sample_evidence)
    controls = status["controls"]
    for cid in ("AU-1", "CM-1", "IA-1", "MA-1", "MP-1", "PE-1", "PS-1", "RA-1", "SC-1", "SI-1"):
        assert cid in controls


def test_mapper_policy_docs_upgrade_matched_controls(sample_evidence):
    status = nist_800_171.map(sample_evidence)
    ac1 = status["controls"]["AC-1"]
    assert ac1["status"] == "COMPLIANT"
    assert any("SharePoint" in e.get("source", "") for e in ac1["evidence"])

    cm1 = status["controls"]["CM-1"]
    assert cm1["status"] == "COMPLIANT"
    assert cm1["maturity"] == "Automated"


def test_mapper_policy_controls_not_addressed_when_no_doc(sample_evidence):
    status = nist_800_171.map(sample_evidence)
    ra1 = status["controls"]["RA-1"]
    assert ra1["status"] == "NOT_ADDRESSED"
    assert any("No matching policy document" in g for g in ra1["gaps"])


def test_mapper_policy_controls_not_addressed_when_no_collector(sample_evidence):
    evidence = {k: v for k, v in sample_evidence.items() if k != "policies"}
    status = nist_800_171.map(evidence)
    cm1 = status["controls"]["CM-1"]
    assert cm1["status"] == "NOT_ADDRESSED"
    assert any("not configured" in g or "unreachable" in g for g in cm1["gaps"])
