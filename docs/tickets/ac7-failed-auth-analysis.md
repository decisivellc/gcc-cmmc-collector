# Analyze signIn logs for AC-7 (failed-auth, lockout)

## Problem

AC-7 (Unsuccessful Logon Attempts) requires evidence that the system enforces a limit on consecutive failed attempts and locks accounts appropriately. We already have the `AuditLog.Read.All` permission that grants access to `/auditLogs/signIns`, but no collector analyzes it. AC-7 is currently uncovered.

## Proposed shape

- Azure AD collector: add a `_collect_sign_in_failures` method that queries `/auditLogs/signIns` with a filter for failed results in the past 30 days.
- Aggregate: count of failures by user, distribution over time, presence of lockout events (`errorCode == 50053` or similar).
- Emit into evidence as `signInFailures` with `{totalFailures, uniqueUsers, lockoutsObserved, topUsers}`.
- New mapper for AC-7: COMPLIANT if Entra smart lockout is observable (any lockout event in window) and failure volume is within expected bounds; PARTIAL if failures visible but no lockouts; NOT_ADDRESSED if the log is empty.

## Acceptance

- AC-7 appears in `CONTROL_IDS` with a dedicated mapper.
- Evidence includes concrete counts from the past 30 days.
- Failure patterns for a single user (potential brute force) are called out as a finding.

## Estimate

1 day.

## Priority

Medium. Adds a real control we don't cover today.
