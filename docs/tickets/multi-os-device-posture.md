# Drop macOS-only filter — report posture for every enrolled platform

## Problem

The Intune collector is hard-filtered to `operatingSystem == 'macOS'`. Real tenants have iOS, iPadOS, Windows, and Android devices enrolled alongside macOS. The current run against the sample tenant shows `Default iOS Compliance Policy` has 3/4 devices non-compliant and `Default Windows Compliance Policy` has 4/4 non-compliant — completely invisible in the report because those devices are filtered out.

## Proposed shape

- Change `collectors.intune.filter_os` default from `"macOS"` to `null` (meaning "all platforms").
- When `null`, collect every managed device; group in the report by operating system.
- Retain the config knob so users who explicitly want to scope can still do so.
- Report template: Device Compliance section gets per-OS tabs or grouped tables (macOS / iOS / Windows / Android).
- Family heatmap includes per-OS summary where applicable.

## Acceptance

- Default run reports devices across every platform.
- Existing tests still pass with an updated fixture that includes a mix.
- README / SETUP updated to reflect default behavior.

## Estimate

½ day.

## Priority

High. Current default silently hides non-compliance.
