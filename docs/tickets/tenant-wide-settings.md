# Tenant-wide settings collector

## Problem

Several CMMC-relevant tenant settings are silent in the report today: whether security defaults are on or off, whether users can register applications by default, what named locations are defined, what self-service password reset is set to, and group expiration policies. These are fast wins — no new Graph permissions, just additional `/policies/...` and `/groupSettings` reads — but they're significant signals for AC-3, AC-6, IA-5, and SC-7.

## Proposed shape

New collector `collectors/tenant_settings.py` that pulls:

- `/policies/identitySecurityDefaultsEnforcementPolicy` — security defaults state.
- `/policies/authorizationPolicy` — already partially read by the password-policy collector; extend to capture `defaultUserRolePermissions` separately and at the top of the evidence (not buried under password).
- `/identity/conditionalAccess/namedLocations` — known IPs / countries / trusted ranges.
- `/policies/authenticationMethodsPolicy` — what auth methods are enabled, MFA registration policy.
- `/groupSettings` — group expiration policies, if any.

Mapper refinements:

- AC-6 evidence gains a "default user role permissions" block (allowedToCreateApps, allowedToCreateSecurityGroups, allowedToCreateTenants, allowedToReadOtherUsers).
- AC-3 / SC-7 mention named locations when present.
- IA-2 / IA-5 mention authentication methods policy when it provides a stronger signal than CA alone.

## Acceptance

- Tenant settings appear in `evidence.tenant_settings` as a structured object.
- Report shows when security defaults are enabled (mutually exclusive with CA mode — finding if both look configured).
- AC-6 mapper specifically calls out `allowedToCreateApps: true` as a least-privilege concern.
- Mocked tests for the new endpoints.

## Estimate

½ day.

## Priority

High. Smallest effort, broadest impact — picks up several latent signals already accessible.
