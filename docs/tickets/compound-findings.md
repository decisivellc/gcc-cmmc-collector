# Escalate compound findings to a critical top-of-report banner

## Problem

The report enumerates findings independently: "3 privileged accounts without MFA", "1 inactive account", "3 Global Administrators". A reader has to mentally correlate — the fact that the SAME account is stale AND privileged AND missing MFA never surfaces as one triple-critical finding. That triangulation is exactly where assessors' eyes go first; the tool should do it upfront.

## Proposed shape

- New analysis pass after the control mappers: walk `evidence.azure_ad.users` and score each account against a risk matrix.
- Risk factors with weights: no MFA, privileged role, inactive >30 days, inactive >90 days, never signed in, enabled, standing vs PIM-managed admin.
- Accounts that hit a threshold (2+ overlapping factors) go into a "Critical Findings" section rendered at the top of the report, above Overall Readiness.
- Each finding is a one-line severity-colored card: "`SeanKMADM` — stale 106 days, enabled, no MFA, has privileged naming convention. Disable or rotate."
- Each card hot-links to the user via the existing `admin_links` machinery.

## Acceptance

- Critical Findings section renders only when at least one account hits the threshold.
- Severity colors match the existing badge system.
- Internal IT can scan the top of the report and immediately see the 3 most urgent accounts.

## Estimate

½ day.

## Priority

High. Very low cost, high visibility value — does the triangulation users would otherwise do manually.
