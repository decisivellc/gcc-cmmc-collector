# Stamp every evidence bullet with a freshness timestamp

## Problem

Graph data isn't real-time. `signInActivity.lastSignInDateTime` lags 6+ hours, `secureScore` is daily, `directoryAudits` has its own propagation delay. The report currently shows a single "collected_at" in the header and implies every data point is equally current. A reader looking at "0 sign-in events in 90 days" can't tell whether that's real or Graph hasn't caught up yet.

## Proposed shape

- Extend each collector to capture the effective freshness of each signal it emits — the API endpoint's documented staleness, plus the request timestamp.
- Evidence records grow a `freshnessLabel` field, e.g. `"up to 6 hours stale (Graph signInActivity)"` or `"real-time"`.
- HTML template renders the freshness label as a muted sub-label on each evidence bullet.

## Acceptance

- Every evidence bullet either has a freshness label or is explicitly labelled "real-time".
- Readme documents the staleness expectation per data source.

## Estimate

½ day.

## Priority

Medium. Important for trust but not blocking any workflow.
