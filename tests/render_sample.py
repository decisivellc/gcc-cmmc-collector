"""Render a sample compliance report from tests/sample_data.json.

Usage: ``python tests/render_sample.py``

Writes ``reports/sample-report.html`` so contributors can preview the
report UI without a real tenant. The output is committed so the README
can link to it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main  # noqa: E402
from mappers import nist_800_171  # noqa: E402


FIXED_DATETIME = "2099-04-20T14:30:00+00:00"
FIXED_HEADER = "2099-04-20 14:30 UTC"


def render() -> Path:
    data_path = Path(__file__).resolve().parent / "sample_data.json"
    with data_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    evidence = {
        "collected_at": FIXED_DATETIME,
        "tenant_id": "sample-tenant",
        **data,
    }
    compliance = nist_800_171.map(evidence)
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(main.TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html")
    html = template.render(
        report_date=FIXED_HEADER,
        collected_at=evidence["collected_at"],
        summary=compliance.get("summary", {}),
        control_families=main._group_by_family(compliance.get("controls", {})),
        devices=(evidence["intune"].get("devices") or []),
        intune_available=bool(evidence["intune"].get("devices")),
        user_summary=main._user_summary(evidence["azure_ad"]),
        remediation=nist_800_171.generate_remediation_backlog(compliance),
    )
    output_dir = ROOT / "reports"
    output_dir.mkdir(exist_ok=True)
    output = output_dir / "sample-report.html"
    output.write_text(html, encoding="utf-8")
    return output


if __name__ == "__main__":
    path = render()
    print(f"Wrote {path}")
