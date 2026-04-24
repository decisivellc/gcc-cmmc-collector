"""Tests for the email_security collector — no real DNS calls."""

from __future__ import annotations

from unittest.mock import MagicMock

from collectors import email_security
from collectors.email_security import (
    _check_domain,
    _evaluate_dkim,
    _evaluate_dmarc,
    _evaluate_spf,
    _posture,
)


def test_evaluate_spf_strict():
    result = _evaluate_spf(["v=spf1 include:spf.protection.outlook.com -all"])
    assert result["present"] is True
    assert result["ending"] == "fail"
    assert result["strict"] is True
    assert "spf.protection.outlook.com" in result["includes"]


def test_evaluate_spf_softfail():
    result = _evaluate_spf(["v=spf1 include:x.com ~all"])
    assert result["ending"] == "soft-fail"
    assert result["strict"] is False


def test_evaluate_spf_missing():
    result = _evaluate_spf(["v=something-else"])
    assert result["present"] is False
    assert result["strict"] is False


def test_evaluate_dmarc_strict():
    result = _evaluate_dmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@x.com"])
    assert result["present"] is True
    assert result["policy"] == "reject"
    assert result["strict"] is True


def test_evaluate_dmarc_none_policy_is_not_strict():
    result = _evaluate_dmarc(["v=DMARC1; p=none"])
    assert result["present"] is True
    assert result["policy"] == "none"
    assert result["strict"] is False


def test_evaluate_dmarc_missing():
    assert _evaluate_dmarc([]) == {"present": False, "record": None, "strict": False}


def test_evaluate_dkim_uses_both_microsoft_selectors():
    def resolver(name):
        if name.startswith("selector1."):
            return ["v=DKIM1; k=rsa; p=ABCDEFG"]
        if name.startswith("selector2."):
            return []
        return []
    result = _evaluate_dkim("example.com", resolver)
    assert result["present"] is True
    names = {s["selector"] for s in result["selectors"]}
    assert names == {"selector1", "selector2"}
    assert any(s["present"] for s in result["selectors"])


def test_posture_strong_requires_all_three_strict():
    spf = {"present": True, "strict": True}
    dmarc = {"present": True, "strict": True}
    dkim = {"present": True}
    assert _posture(spf, dmarc, dkim) == "strong"


def test_posture_missing_when_nothing_found():
    assert _posture({"present": False}, {"present": False}, {"present": False}) == "missing"


def test_check_domain_end_to_end_via_stub_resolver():
    def resolver(name):
        mapping = {
            "example.us": ["v=spf1 include:spf.protection.outlook.com -all"],
            "_dmarc.example.us": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.us"],
            "selector1._domainkey.example.us": ["v=DKIM1; k=rsa; p=XYZ"],
            "selector2._domainkey.example.us": [],
        }
        return mapping.get(name, [])
    result = _check_domain("example.us", resolver)
    assert result["domain"] == "example.us"
    assert result["posture"] == "strong"
    assert result["spf"]["strict"] is True
    assert result["dmarc"]["policy"] == "reject"
    assert result["dkim"]["present"] is True


def test_collect_auto_discovers_verified_non_onmicrosoft_domains(monkeypatch):
    class FakeClient:
        def get(self, path, params=None): return {}
        def get_all(self, path, params=None):
            if path == "/domains":
                return [
                    {"id": "contoso.onmicrosoft.us", "isVerified": True},
                    {"id": "contoso.us", "isVerified": True},
                    {"id": "unverified.us", "isVerified": False},
                ]
            return []

    def fake_resolver(name):
        if name == "contoso.us":
            return ["v=spf1 -all"]
        if name == "_dmarc.contoso.us":
            return ["v=DMARC1; p=quarantine"]
        return []

    monkeypatch.setattr(email_security, "_resolve_txt", fake_resolver)
    result = email_security.collect(FakeClient())
    assert result["available"] is True
    assert {d["domain"] for d in result["domains"]} == {"contoso.us"}
    assert result["summary"]["domainsChecked"] == 1
