# App registration inventory collector

## Problem

Apps registered in the tenant are an underrated AC-6 / AC-3 risk. Old apps with high privileges, apps from unverified publishers, recently-granted consent — all are visible to Graph but not surfaced today. Most small-DIB tenants accumulate at least one "huh, what's that?" app that nobody remembers granting consent to.

## Proposed shape

New collector `collectors/app_inventory.py` that pulls:

- `/applications` — apps registered in the tenant (this tool's own app shows up here).
- `/servicePrincipals` — including third-party apps consented to, regardless of who created them.
- For each: granted application + delegated permissions, publisher name and verification state, sign-in activity, created-date.
- Recent consent grants from `/auditLogs/directoryAudits` filtered to consent activities.

Per-app risk flagging:
- Granted high-privilege roles like `Application.ReadWrite.All`, `Mail.ReadWrite`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` → critical.
- Apps with no sign-in activity in 90+ days → stale.
- Apps from unverified publishers → review.

New mapper or AC-6 enrichment surfaces these specifically.

## Permission

Adds `Application.Read.All` to the required app-registration permissions. Document in SETUP.md and the Entra bootstrap.

## Acceptance

- Evidence includes per-app metadata with granted permissions.
- Critical apps (high-privilege OR stale-but-still-consented) surface in the Critical Findings section.
- The collector itself appears in the inventory (as a sanity check) without flagging itself critical.

## Estimate

½ day plus permission grant friction.

## Priority

High. Often catches forgotten shadow IT.
