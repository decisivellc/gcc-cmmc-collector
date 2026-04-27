# Purview sensitivity labels collector

## Problem

Three NIST 800-171r2 requirements specifically cover CUI handling — 3.1.3 (control CUI flow), 3.8.4 (mark CUI media), 3.13.16 (protect CUI at rest) — and all three are currently unmeasured because the tool has no view into Microsoft Purview. For CMMC L2, "are you using sensitivity labels" is a routine assessor question; today the answer is "I don't know" until a human checks the Purview portal.

## Proposed shape

New collector `collectors/purview.py` that pulls:

- `/security/informationProtection/sensitivityLabels` — published label list.
- `/security/informationProtection/sensitivityLabels/{id}` — per-label config (display name, description, color, content marking, encryption, scopes).
- Optionally `/policies/dataClassificationPolicies` for label policies (which users can apply which labels).

Evidence shape: `{labels: [...], publishedCount, labelsWithEncryption, labelsWithMarking}`.

Label posture scoring per requirement:
- 3.1.3 (control CUI flow): label policy exists AND labels include encryption → COMPLIANT.
- 3.8.4 (mark CUI media): at least one label has visible content marking (header/footer/watermark) → COMPLIANT.
- 3.13.16 (protect CUI at rest): at least one label applies encryption to files → COMPLIANT.

New internal control IDs (e.g. SC-13 or MP-3) to carry the evidence; update catalog mapping.

## Permission

Adds `InformationProtectionPolicy.Read.All`. Document in SETUP.md and Entra bootstrap.

## Acceptance

- Evidence enumerates published sensitivity labels.
- Three currently-unmeasured CUI requirements (3.1.3, 3.8.4, 3.13.16) move from `not_measured` to `measured` with concrete evidence when labels are configured.
- Tenants without Purview see a clear "no Purview labels published — required for CUI handling" finding rather than silence.

## Estimate

1 day.

## Priority

Medium-high. Highest-impact unmeasured-NIST-requirement closer (three controls in one collector). Lower priority than tenant settings only because Purview adoption is uneven among small DIBs.
