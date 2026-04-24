"""Coverage analysis against NIST 800-171r2 (CMMC Level 2).

Loads the 110-requirement catalog and correlates it with the measured
control set to produce a per-requirement coverage status that the report
renders below the existing control-by-family section.

Coverage levels:

- ``measured``: at least one non-`-1` technical control contributes
  evidence for the requirement. Its effective status is the best
  (most compliant) among the contributing controls.
- ``policy_only``: only a policy-family ``-1`` control (AC-1, AT-1, etc.)
  contributes evidence. Covered on paper; real enforcement not verified.
- ``not_measured``: no mapping. The catalog entry carries a ``note`` with
  the reason.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CATALOG_PATH = Path(__file__).resolve().parent / "nist_800_171_catalog.json"

STATUS_ORDER = {"COMPLIANT": 0, "PARTIAL": 1, "NOT_ADDRESSED": 2}

LEVEL_MEASURED = "measured"
LEVEL_POLICY_ONLY = "policy_only"
LEVEL_NOT_MEASURED = "not_measured"


def _load_catalog() -> dict[str, Any]:
    with CATALOG_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _is_policy_only(control_id: str) -> bool:
    return control_id.endswith("-1")


def _best_status(statuses: list[str]) -> str | None:
    if not statuses:
        return None
    return min(statuses, key=lambda s: STATUS_ORDER.get(s, 3))


def compute_coverage(
    compliance_status: dict[str, Any],
    attestations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a structured coverage report vs the 110 requirements.

    ``attestations`` is a map of ``requirement_id`` -> attestation record
    (status, rationale, attestedBy, attestedAt, [reviewBy]). Attestations
    fill in the ``effectiveStatus`` for requirements that have no internal
    automated signal. If a requirement has both, the automated signal wins
    but the attestation is still shown as supplementary evidence.
    """
    catalog = _load_catalog()
    controls = (compliance_status or {}).get("controls") or {}
    attestations = attestations or {}

    families: dict[str, dict[str, Any]] = {}
    summary = {LEVEL_MEASURED: 0, LEVEL_POLICY_ONLY: 0, LEVEL_NOT_MEASURED: 0}
    attested_count = 0

    for req in catalog["requirements"]:
        family_key = req["id"].rsplit(".", 1)[0]
        family_bucket = families.setdefault(
            family_key,
            {
                "key": family_key,
                "title": catalog["familyTitles"].get(family_key, family_key),
                "requirements": [],
            },
        )

        measured_by = req.get("measuredBy") or []
        mapping = []
        has_technical = False
        statuses: list[str] = []
        for cid in measured_by:
            control = controls.get(cid)
            status = control.get("status") if control else None
            mapping.append(
                {
                    "controlId": cid,
                    "title": (control or {}).get("title"),
                    "status": status,
                }
            )
            if status:
                statuses.append(status)
            if not _is_policy_only(cid):
                has_technical = True

        if not measured_by:
            level = LEVEL_NOT_MEASURED
        elif has_technical:
            level = LEVEL_MEASURED
        else:
            level = LEVEL_POLICY_ONLY

        summary[level] += 1

        automated_status = _best_status(statuses)
        attestation = attestations.get(req["id"])
        if attestation:
            attested_count += 1

        effective_status = automated_status
        source = "automated" if automated_status else None
        if not effective_status and attestation:
            effective_status = attestation.get("status")
            source = "attestation"

        family_bucket["requirements"].append(
            {
                "id": req["id"],
                "title": req["title"],
                "description": req["description"],
                "coverageLevel": level,
                "note": req.get("note"),
                "mapping": mapping,
                "effectiveStatus": effective_status,
                "effectiveStatusSource": source,
                "attestation": attestation,
            }
        )

    ordered_families = sorted(
        families.values(),
        key=lambda f: tuple(int(x) for x in f["key"].split(".")),
    )
    return {
        "totalRequirements": catalog["totalRequirements"],
        "summary": summary,
        "attestedCount": attested_count,
        "families": ordered_families,
    }
