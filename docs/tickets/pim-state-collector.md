# PIM state collector

## Problem

The current AC-6 mapper credits PIM activation history, but doesn't see the *posture*: who is eligible, what the activation policy actually requires (MFA? approval? max duration?), and how many roles are configured for PIM at all. Without that view, AC-6 says "JayMADM is JIT" without showing whether a Global Administrator activation requires approval, whether MFA-on-activation is enforced, or how long an activation can last.

## Proposed shape

New collector `collectors/pim.py` that pulls:

- `/roleManagement/directory/roleEligibilitySchedules` — eligible role assignments (who *could* activate).
- `/roleManagement/directory/roleAssignmentSchedules` — currently active assignments.
- `/policies/roleManagementPolicies` + `/policies/roleManagementPolicyAssignments` — activation requirements per role (MFA, approval, max duration, justification).
- Cross-reference with `/directoryRoles` for human-readable role names.

Evidence shape:
- Per role: `{eligibleCount, activeCount, requiresMfa, requiresApproval, maxDurationHours, requiresJustification}`.
- Top-level: `{totalEligible, totalActive, weakActivationPolicies}` where "weak" means GA-equivalent without MFA-on-activation or approval.

AC-6 mapper enrichment:
- Add evidence rows for PIM activation policy quality.
- Flag any high-privilege role with weak activation policy as a finding.
- Reduce "standing admin" count by anyone counted as eligible but not currently active.

## Permission

Adds `RoleManagement.Read.Directory`. Document in SETUP.md and Entra bootstrap.

## Acceptance

- AC-6 evidence shows "Global Admin: 2 active, 4 eligible-via-PIM with MFA + approval required" instead of just "2 standing admins".
- Weak activation policies (no MFA, no approval) are flagged as gaps.
- The 'standing_admin' factor in critical findings excludes users who are PIM-eligible but not active.

## Estimate

1 day.

## Priority

High. Significantly refines AC-6 truth, which is a top-of-report finding for most tenants.
