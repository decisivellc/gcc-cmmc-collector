# Collect Intune configuration profiles (CM-2, CM-6)

## Problem

CM-2 (Baseline Configuration) and CM-6 (Configuration Settings) require a documented baseline applied to devices. We currently list Intune **compliance policies** (policy exists / enforced state) but not **configuration profiles** — the settings catalog / device-configuration / endpoint-security profiles that actually carry the baseline hardening.

## Proposed shape

- Extend `collectors/intune.py` with a `_collect_config_profiles` method.
- Query `/deviceManagement/deviceConfigurations` (legacy) and `/deviceManagement/configurationPolicies` (settings catalog).
- For each profile capture: name, platforms, assignment count, last-modified date, and `deviceStatusOverview` (successes vs errors).
- Also pull `/deviceManagement/intents` for endpoint security profiles (antivirus, disk encryption, firewall).
- Evidence output: summary counts per profile type and per platform, plus per-profile rollup.
- Update CM-2 and CM-6 mappers (new controls) to consume the signal. COMPLIANT when the tenant has at least one config profile per enforced platform with >0 successful deployments.

## Acceptance

- CM-2 and CM-6 appear in the controls list.
- Evidence names the profiles found (clickable via the existing admin-links machinery).
- Tested against a mock client covering both legacy and settings-catalog shapes.

## Estimate

1 day.

## Priority

High. CM-2 / CM-6 are near-universal findings in CMMC audits; this tool has been silent on them.
