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


def compute_coverage(compliance_status: dict[str, Any]) -> dict[str, Any]:
    """Return a structured coverage report vs the 110 requirements.

    Shape:
        {
            "totalRequirements": 110,
            "summary": {"measured": N, "policy_only": M, "not_measured": K},
            "families": [
                {"key": "3.1", "title": "Access Control", "requirements": [...]}
            ],
        }

    Each requirement carries ``coverageLevel`` and, when a control-based
    mapping exists, ``effectiveStatus`` (best of mapped controls) plus
    the list of mapping controls with their individual statuses.
    """
    catalog = _load_catalog()
    controls = (compliance_status or {}).get("controls") or {}

    families: dict[str, dict[str, Any]] = {}
    summary = {LEVEL_MEASURED: 0, LEVEL_POLICY_ONLY: 0, LEVEL_NOT_MEASURED: 0}

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

        family_bucket["requirements"].append(
            {
                "id": req["id"],
                "title": req["title"],
                "description": req["description"],
                "coverageLevel": level,
                "note": req.get("note"),
                "mapping": mapping,
                "effectiveStatus": _best_status(statuses),
            }
        )

    ordered_families = sorted(
        families.values(),
        key=lambda f: tuple(int(x) for x in f["key"].split(".")),
    )
    return {
        "totalRequirements": catalog["totalRequirements"],
        "summary": summary,
        "families": ordered_families,
    }
