# Drill down Secure Score into actionable recommendations

## Problem

The report shows "Secure Score: 350.88 / 471". That's a number, not a to-do list. Microsoft publishes per-recommendation gap data via `/security/secureScores/{id}/controlProfiles` and `/security/secureScoreControlProfiles` — which specific recommendations are incomplete, their point value, impact, and remediation path. None of this is surfaced today.

## Proposed shape

- Extend `collectors/defender.py` with a `_collect_secure_score_actions` method that pulls `/security/secureScoreControlProfiles` (metadata) and joins with the latest `secureScores.controlScores` (achieved state).
- Emit a ranked list of incomplete recommendations: `{controlName, currentScore, maxScore, actionType, remediation, implementationCost}`.
- Dashboard section: "Top Secure Score wins" — 5 highest-point recommendations the user can close.
- Hot-link each to its Defender admin page via `admin_links`.

## Acceptance

- "Secure Score" section grows from a raw number to a prioritized recommendation list.
- Points-available is accurate against Microsoft's live metadata.
- Empty / zero-score recommendations are filtered.

## Estimate

1 day.

## Priority

Medium. Turns an opaque percentage into a ranked backlog that IT staff can attack directly.
