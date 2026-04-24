# Add explicit coverage map — controls we don't measure

## Problem

CMMC Level 2 has 110 controls. This tool measures 28. Today that's implicit — the report shows 28 controls without declaring the other 82 exist. A reader could reasonably (and wrongly) infer that 28 is the whole universe, which overclaims the tool's scope.

## Proposed shape

- Hand-curate a JSON file enumerating all 110 CMMC L2 / NIST 800-171r2 controls: ID, family, short title.
- For each control not in the mapper, record WHY it's not measured: "requires Purview API", "requires physical inspection", "policy-only — covered indirectly via the -1 family policy doc", etc.
- New "Coverage Map" section at the bottom of the report, grouped by family, showing which controls are:
  - measured (green)
  - policy-doc only (yellow)
  - not measured with reason (grey)

## Acceptance

- Every CMMC L2 control appears somewhere in the report's coverage map with an explicit status.
- README "What it does" section updates to name the coverage fraction honestly.

## Estimate

1 day — most of the effort is the curated control list and reason text.

## Priority

Medium-high. Kills the implicit overclaim; needed before this tool gets used as input to any external assessment.
