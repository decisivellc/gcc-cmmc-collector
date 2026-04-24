"""Tests for admin portal deep-link generation."""

from __future__ import annotations

import admin_links


SAMPLE_EVIDENCE = {
    "azure_ad": {
        "users": [
            {
                "id": "user-1",
                "userPrincipalName": "admin@contoso.onmicrosoft.us",
                "displayName": "Decisive Admin",
            },
            {
                "id": "user-2",
                "userPrincipalName": "jay@contoso.us",
                "displayName": "Jay",
            },
        ],
        "conditionalAccessPolicies": [
            {"id": "pol-1", "displayName": "Require MFA for admins", "state": "enabled"},
        ],
    },
    "intune": {
        "devices": [
            {"id": "dev-1", "deviceName": "Jay's MacBook"},
        ],
    },
}


def test_build_link_index_covers_users_policies_and_devices():
    idx = admin_links.build_link_index(SAMPLE_EVIDENCE)
    assert "admin@contoso.onmicrosoft.us" in idx
    assert "jay@contoso.us" in idx
    assert "Require MFA for admins" in idx
    assert "Jay's MacBook" in idx
    assert "user-1" in idx["admin@contoso.onmicrosoft.us"]
    assert "pol-1" in idx["Require MFA for admins"]
    assert "dev-1" in idx["Jay's MacBook"]


def test_linkify_wraps_known_tokens_only():
    idx = admin_links.build_link_index(SAMPLE_EVIDENCE)
    text = "Gap: admin@contoso.onmicrosoft.us missing MFA; unknown@contoso.us is fine."
    result = admin_links.linkify(text, idx)
    assert 'href="https://entra.microsoft.us' in result
    assert 'admin@contoso.onmicrosoft.us</a>' in result
    # Unknown UPN should NOT be wrapped.
    assert 'unknown@contoso.us</a>' not in result


def test_linkify_does_not_match_partial_tokens():
    """``jay@contoso.us`` must not match inside ``jay@contoso.usa``."""
    idx = admin_links.build_link_index(SAMPLE_EVIDENCE)
    text = "Visit jay@contoso.usa for help."
    result = admin_links.linkify(text, idx)
    assert "<a" not in result


def test_linkify_prefers_longer_matches():
    """``admin@contoso.onmicrosoft.us`` must match before shorter ``admin``
    would if the shorter one were also indexed."""
    idx = {
        "admin": "http://short/",
        "admin@contoso.onmicrosoft.us": "http://long/",
    }
    text = "admin@contoso.onmicrosoft.us is the target."
    result = admin_links.linkify(text, idx)
    assert "http://long/" in result
    assert "http://short/" not in result


def test_linkify_escapes_html_in_input():
    idx = {}
    text = "<script>alert(1)</script>"
    result = admin_links.linkify(text, idx)
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


def test_linkify_handles_empty_inputs():
    assert admin_links.linkify("", {}) == ""
    assert admin_links.linkify(None, {}) == ""
    assert admin_links.linkify("plain text", {}) == "plain text"
