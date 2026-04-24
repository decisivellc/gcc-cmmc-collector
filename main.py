"""CLI entry point for the CMMC GCC-High evidence collector."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

import admin_links
from collectors import azure_ad, defender, exchange, intune, policies
from graph_client import GraphClient
from mappers import coverage, nist_800_171

logger = logging.getLogger("cmmc.main")


TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

COLLECTOR_FUNCTIONS = {
    "azure_ad": azure_ad.collect,
    "intune": intune.collect,
    "defender": defender.collect,
    "exchange": exchange.collect,
    "policies": policies.collect,
}

PLACEHOLDER_VALUES = {
    "YOUR_TENANT_ID_HERE",
    "YOUR_APP_ID_HERE",
    "YOUR_CLIENT_SECRET_HERE",
}


class ConfigError(ValueError):
    """Raised when config.json is missing values or contains placeholders."""


def load_config(config_path: str) -> dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {config_path}")
    with path.open("r", encoding="utf-8") as fh:
        config = json.load(fh)

    env_secret = os.environ.get("CMMC_CLIENT_SECRET")
    if env_secret:
        config["client_secret"] = env_secret

    for field in ("tenant_id", "client_id", "client_secret"):
        value = config.get(field)
        if not value or value in PLACEHOLDER_VALUES:
            raise ConfigError(
                f"Config field '{field}' contains a placeholder or is empty. "
                "Fill in your tenant values (or set CMMC_CLIENT_SECRET env var)."
            )
    config.setdefault("authority", "https://login.microsoftonline.us")
    config.setdefault("graph_base_url", "https://graph.microsoft.us/v1.0")
    config.setdefault("collectors", {})
    return config


def authenticate(config: dict[str, Any]) -> GraphClient:
    return GraphClient(
        tenant_id=config["tenant_id"],
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        authority=config.get("authority"),
        graph_base_url=config.get("graph_base_url"),
    )


def _enabled_collectors(config: dict[str, Any]) -> list[str]:
    cfg = config.get("collectors") or {}
    enabled: list[str] = []
    for name in COLLECTOR_FUNCTIONS:
        settings = cfg.get(name) or {}
        if settings.get("enabled", True):
            enabled.append(name)
    return enabled


def run_collection(
    client: GraphClient,
    enabled: list[str],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = config or {}
    collector_settings = config.get("collectors") or {}
    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max(len(enabled), 1)) as executor:
        futures = {}
        for name in enabled:
            fn = COLLECTOR_FUNCTIONS[name]
            settings = collector_settings.get(name) or {}
            if name == "policies":
                call = lambda c=client, s=settings: fn(c, s.get("site_url", ""))
            else:
                call = lambda c=client, f=fn: f(c)
            futures[executor.submit(call)] = name
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                logger.warning("Collector %s failed: %s", name, exc)
                results[name] = {"available": False, "error": str(exc)}
    for name in enabled:
        results.setdefault(name, {"available": False, "error": "collector did not run"})
    return results


def generate_report(compliance_status: dict[str, Any], evidence: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    link_index = admin_links.build_link_index(evidence)
    env.filters["linkify"] = lambda text: admin_links.linkify(text, link_index)
    template = env.get_template("report.html")
    controls = compliance_status.get("controls", {})
    grouped = _group_by_family(controls)
    remediation = nist_800_171.generate_remediation_backlog(compliance_status)
    intune_data = evidence.get("intune") or {}
    azure_data = evidence.get("azure_ad") or {}
    return template.render(
        report_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        collected_at=evidence.get("collected_at"),
        summary=compliance_status.get("summary", {}),
        readiness=_build_readiness(compliance_status, remediation),
        control_families=grouped,
        devices=(intune_data.get("devices") or []),
        intune_available=bool(intune_data.get("devices")),
        user_summary=_user_summary(azure_data),
        remediation=remediation,
        collection_warnings=evidence.get("collection_warnings") or [],
        policies=evidence.get("policies") or {},
        secure_score_url=admin_links.secure_score_url(),
        coverage=coverage.compute_coverage(compliance_status),
    )


def _flatten_collection_warnings(collected: dict[str, Any]) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    for data in collected.values():
        if isinstance(data, dict):
            warnings.extend(data.get("_collectionWarnings") or [])
    return warnings


def generate_remediation_backlog(compliance_status: dict[str, Any]) -> dict[str, Any]:
    return nist_800_171.generate_remediation_backlog(compliance_status)


def _group_by_family(controls: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for control_id, entry in controls.items():
        family = entry.get("family", control_id.split("-")[0])
        enriched = {"id": control_id, **entry}
        buckets.setdefault(family, []).append(enriched)
    ordered_families = ["AC", "IA", "AU", "SC", "SI", "IR", "AT"]
    result = []
    for family in ordered_families:
        if family in buckets:
            result.append(
                {
                    "key": family,
                    "title": nist_800_171.FAMILY_TITLES.get(family, family),
                    "controls": buckets[family],
                }
            )
    for family, controls_list in buckets.items():
        if family not in ordered_families:
            result.append(
                {"key": family, "title": family, "controls": controls_list}
            )
    return result


def _build_readiness(
    compliance_status: dict[str, Any],
    remediation: dict[str, Any],
) -> dict[str, Any]:
    controls = compliance_status.get("controls", {}) or {}
    families: dict[str, dict[str, Any]] = {}
    for cid, control in controls.items():
        family = control.get("family", cid.split("-")[0])
        bucket = families.setdefault(
            family,
            {"key": family, "title": nist_800_171.FAMILY_TITLES.get(family, family),
             "total": 0, "compliant": 0, "partial": 0, "notAddressed": 0},
        )
        bucket["total"] += 1
        status = control.get("status")
        if status == "COMPLIANT":
            bucket["compliant"] += 1
        elif status == "PARTIAL":
            bucket["partial"] += 1
        else:
            bucket["notAddressed"] += 1
    family_rows: list[dict[str, Any]] = []
    for row in families.values():
        total = row["total"] or 1
        row["pct"] = round(((row["compliant"] * 1.0 + row["partial"] * 0.5) / total) * 100)
        family_rows.append(row)
    family_rows.sort(key=lambda r: (r["pct"], r["key"]))

    bucket_order = {"quick_win": 0, "medium": 1, "heavy_lift": 2}
    gaps: list[dict[str, Any]] = []
    for cid, control in controls.items():
        if control.get("status") == "COMPLIANT":
            continue
        remediation_info = control.get("remediation") or {}
        gaps.append({
            "id": cid,
            "title": control.get("title"),
            "status": control.get("status"),
            "firstGap": (control.get("gaps") or [""])[0],
            "effort": remediation_info.get("effort", "Unknown"),
            "bucket": remediation_info.get("bucket", "medium"),
        })
    gaps.sort(key=lambda g: (
        0 if g["status"] == "NOT_ADDRESSED" else 1,
        bucket_order.get(g["bucket"], 1),
    ))

    quick_win_count = sum(
        1 for tasks in (remediation.get("quick_win") or [])
        if tasks.get("status") != "COMPLIANT"
    )

    summary = compliance_status.get("summary", {}) or {}
    total_controls = len(controls)
    return {
        "total": total_controls,
        "compliant": summary.get("compliant", 0),
        "partial": summary.get("partial", 0),
        "notAddressed": summary.get("notAddressed", 0),
        "automatedMaturity": summary.get("automatedMaturity", 0),
        "percentage": summary.get("overallPercentage", 0),
        "quickWins": quick_win_count,
        "familyRows": family_rows,
        "topGaps": gaps[:5],
    }


def _user_summary(azure: dict[str, Any]) -> dict[str, Any]:
    users = azure.get("users") or []
    active = [u for u in users if u.get("accountEnabled")]
    mfa = [u for u in active if u.get("mfaStatus") == "enabled"]
    inactive = [
        u for u in active
        if isinstance(u.get("lastActiveInDays"), int) and u["lastActiveInDays"] > 30
    ]
    mfa_percent = round((len(mfa) / len(active)) * 100) if active else 0
    return {
        "total": len(users),
        "active": len(active),
        "mfaCount": len(mfa),
        "mfaPercent": mfa_percent,
        "inactive": len(inactive),
    }


def write_outputs(
    evidence: dict[str, Any],
    compliance_status: dict[str, Any],
    remediation: dict[str, Any],
    html_report: str,
    output_dir: Path,
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = output_dir / "evidence.json"
    report_path = output_dir / "compliance-report.html"
    remediation_path = output_dir / "remediation-backlog.json"

    evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    report_path.write_text(html_report, encoding="utf-8")
    remediation_path.write_text(json.dumps(remediation, indent=2), encoding="utf-8")
    return {
        "evidence": evidence_path,
        "report": report_path,
        "remediation": remediation_path,
    }


def run_pipeline(config: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    """Run authentication, collection, mapping, and report writing.

    Returns a dict with keys ``outputs`` (paths), ``summary`` (compliance
    summary), and ``readiness`` (template-ready breakdown). Callers include
    the CLI (main) and the Flask web app.
    """
    client = authenticate(config)
    enabled = _enabled_collectors(config)
    logger.info("Running collectors in parallel: %s", ", ".join(enabled))
    collected = run_collection(client, enabled, config)

    evidence = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": config["tenant_id"],
        "collection_warnings": _flatten_collection_warnings(collected),
        **collected,
    }
    compliance_status = nist_800_171.map(evidence)
    remediation = generate_remediation_backlog(compliance_status)
    html = generate_report(compliance_status, evidence)
    outputs = write_outputs(
        evidence,
        compliance_status,
        remediation,
        html,
        output_dir,
    )
    return {
        "outputs": outputs,
        "summary": compliance_status.get("summary", {}),
        "readiness": _build_readiness(compliance_status, remediation),
        "collection_warnings": evidence["collection_warnings"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cmmc-gcc-collector",
        description="Collect CMMC pre-assessment evidence from a GCC-High tenant.",
    )
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument(
        "--output", default="./reports", help="Output directory (default: ./reports)"
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("CMMC_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        logger.error("Config error: %s", exc)
        return 2

    try:
        result = run_pipeline(config, Path(args.output))
    except Exception as exc:
        logger.error("Pipeline failed: %s", exc)
        return 3

    logger.info("Report generated: %s", result["outputs"]["report"])
    print(f"Report generated: {result['outputs']['report']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
