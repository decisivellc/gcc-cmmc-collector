# Multi-run history, trend visualization, and tenant diff

## Problem

Each run overwrites `reports/compliance-report.html` and `reports/evidence.json`. There's no way to see "did our readiness improve since last week?", and no way to know what specifically changed. For a tool meant to drive ongoing readiness improvement, this is a missing core workflow.

## Proposed shape

- Archive each run under `reports/archive/<UTC-ISO-date>/` (evidence, compliance, HTML, remediation).
- New "History" page in the web UI showing a chronological list of runs with overall % and delta.
- Per-control trend sparklines in the HTML report ("this control has been PARTIAL for 3 weeks").
- Diff between the current run and the previous (or any picked prior): controls that changed status, newly-flagged findings, newly-resolved ones.
- Retention config: `reporting.history_retention_days` (default 365) — pruned automatically.

## Acceptance

- Running the collector creates a new archive folder; `reports/compliance-report.html` still reflects the latest.
- Web UI `/history` shows runs in reverse chronological order.
- Each run page links to "diff vs previous" that highlights the delta.

## Estimate

1-2 days.

## Priority

High. Biggest single change to how the tool feels over time.
