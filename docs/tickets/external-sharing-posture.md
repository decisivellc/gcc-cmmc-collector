# External sharing posture — AC-20 / AC-21

## Problem

AC-20 (Use of External Systems) and AC-21 (Information Sharing) turn heavily on SharePoint/OneDrive external sharing settings: tenant-level guest access, per-site sharing levels, link expiration, allow/block domain lists. None of this is collected today.

## Proposed shape

- Add `Sites.FullControl.All` **or** `SharePointTenantSettings.Read.All` to the required Graph permissions (document the choice; the latter is more conservative if it's sufficient).
- New collector `collectors/sharing.py`.
- Fetches:
  - Tenant-level sharing settings (`/admin/sharepoint/settings`).
  - Per-site overrides from the top N most-active sites.
  - Guest accounts via `/users?$filter=userType eq 'Guest'`.
- Evidence: tenant sharing level (external / authenticatedGuest / existingGuest / disabled), guest count, expiration settings, domain allow/block lists.
- New mappers AC-20 and AC-21 consuming the signal.

## Acceptance

- Both AC-20 and AC-21 appear in the control list with real evidence.
- README and SETUP updated with the added permission and consent requirement.
- Works when the permission is granted; degrades gracefully with a specific warning when it's not.

## Estimate

1 day including permission docs and tests.

## Priority

Medium-high. Real controls that CMMC assessors scrutinize closely for CUI handlers.
