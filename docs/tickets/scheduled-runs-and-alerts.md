# Scheduled runs and delta alerts

## Problem

The tool runs on demand — either `python main.py --config …` or a web-UI button click. Keeping a continuous pulse on readiness currently requires a human remembering to push the button. For internal IT readiness tracking, weekly (or nightly) runs with an alert when something regresses is the expected workflow.

## Proposed shape

- Add a `schedule` block to `config.json` with `{enabled: bool, cron: str}`.
- In the Docker container, run a small scheduler (APScheduler or plain cron wrapping `python main.py`) that triggers runs at the configured cadence.
- After each scheduled run, compute a delta vs the prior run (depends on multi-run history ticket).
- Alert delivery options: Teams incoming webhook URL (GCC-High compatible), SMTP (configurable), or write a structured `reports/alerts.log`.
- Alert content: controls that regressed (status downgraded), new critical findings (admin without MFA, new stale admin, etc.).

## Acceptance

- Scheduled runs execute without user interaction.
- Regressions trigger an alert to the configured channel.
- Steady-state (nothing changed) does not alert.
- Web UI shows next scheduled run time and most recent scheduled run status.

## Estimate

1 day.

## Priority

High. Pairs with history ticket; together they change the tool from one-shot to continuous.

## Depends on

Multi-run history ticket.
