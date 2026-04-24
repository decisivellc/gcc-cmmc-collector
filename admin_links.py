"""Build deep-link URLs into the GCC-High admin portals.

These URLs let a report reader click a user/policy/device name and land
on the matching Entra/Intune edit page. The portal hostnames are
hard-coded for GCC-High (``.us`` suffix); override by editing here if
you adapt the tool to commercial M365.
"""

from __future__ import annotations

import re
from html import escape
from typing import Any

PORTAL_ENTRA = "https://entra.microsoft.us"
PORTAL_INTUNE = "https://intune.microsoft.us"
PORTAL_DEFENDER = "https://security.microsoft.us"


def user_url(user_id: str) -> str:
    return (
        f"{PORTAL_ENTRA}/#view/Microsoft_AAD_UsersAndTenants/"
        f"UserProfileMenuBlade/~/overview/userId/{user_id}"
    )


def ca_policy_url(policy_id: str) -> str:
    return (
        f"{PORTAL_ENTRA}/#view/Microsoft_AAD_ConditionalAccess/"
        f"PolicyBlade/policyId/{policy_id}"
    )


def device_url(device_id: str) -> str:
    return (
        f"{PORTAL_INTUNE}/#view/Microsoft_Intune_Devices/"
        f"DeviceSettingsBlade/deviceId/{device_id}"
    )


def secure_score_url() -> str:
    return f"{PORTAL_DEFENDER}/securescore"


def build_link_index(evidence: dict[str, Any]) -> dict[str, str]:
    """Return a map of token (UPN or display name) -> admin portal URL.

    Used by the ``linkify`` Jinja filter to hot-link tokens appearing in
    free-form evidence and gap strings.
    """
    index: dict[str, str] = {}
    azure = evidence.get("azure_ad") or {}
    for user in azure.get("users") or []:
        upn = user.get("userPrincipalName")
        uid = user.get("id")
        if upn and uid:
            index[upn] = user_url(uid)
        # Also key by displayName in case evidence references it.
        name = user.get("displayName")
        if name and uid and name not in index:
            index[name] = user_url(uid)
    for policy in azure.get("conditionalAccessPolicies") or []:
        display = policy.get("displayName")
        pid = policy.get("id")
        if display and pid:
            index[display] = ca_policy_url(pid)
    intune = evidence.get("intune") or {}
    for device in intune.get("devices") or []:
        did = device.get("id")
        name = device.get("deviceName")
        if did and name and name not in index:
            index[name] = device_url(did)
    return index


# Sort keys by length (longest first) so "admin@decisivellc.onmicrosoft.us"
# is matched before the shorter "admin" substring.
def linkify(text: str, index: dict[str, str]) -> str:
    """Return text with known tokens wrapped in anchor tags.

    Input text is escaped; replacements use ``Markup`` so the result is
    safe to render with ``| safe`` downstream. Whole-token matches only,
    bounded by non-word characters to avoid partial-word collisions.
    """
    if not text:
        return ""
    safe = escape(str(text))
    if not index:
        return safe
    tokens = sorted(index.keys(), key=len, reverse=True)
    for token in tokens:
        url = index[token]
        escaped_token = escape(token)
        pattern = re.compile(
            r"(?<![A-Za-z0-9._@-])" + re.escape(escaped_token) + r"(?![A-Za-z0-9._@-])"
        )
        replacement = (
            f'<a href="{escape(url)}" target="_blank" rel="noopener">'
            f"{escaped_token}</a>"
        )
        safe = pattern.sub(replacement, safe)
    return safe
