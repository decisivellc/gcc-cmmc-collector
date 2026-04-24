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
import attestations as attestations_store
import critical_findings
import history
from collectors import azure_ad, defender, email_security, exchange, intune, policies
from graph_client import GraphClient
from mappers import coverage, nist_800_171

logger = logging.getLogger("cmmc.main")


TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

COLLECTOR_FUNCTIONS = {
    "azure_ad": azure_ad.collect,
    "intune": intune.collect,
    "defender": defender.collect,
    "exchange": exchange.collect,
    "email_security": email_security.collect,
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
            elif name == "intune":
                call = lambda c=client, s=settings: fn(c, s.get("filter_os") or None)
            elif name == "email_security":
                call = lambda c=client, s=settings: fn(c, s.get("domains") or None)
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


def generate_report(
    compliance_status: dict[str, Any],
    evidence: dict[str, Any],
    attestations: dict[str, dict[str, Any]] | None = None,
) -> str:
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
    attestations = attestations or {}
    return template.render(
        report_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        collected_at=evidence.get("collected_at"),
        summary=compliance_status.get("summary", {}),
        readiness=_build_readiness(compliance_status, remediation, attestations),
        control_families=grouped,
        devices=(intune_data.get("devices") or []),
        intune_available=bool(intune_data.get("devices")),
        intune_by_os=intune_data.get("deviceComplianceByOs") or [],
        intune_os_filter=intune_data.get("osFilter"),
        user_summary=_user_summary(azure_data),
        remediation=remediation,
        collection_warnings=evidence.get("collection_warnings") or [],
        policies=evidence.get("policies") or {},
        secure_score_url=admin_links.secure_score_url(),
        coverage=coverage.compute_coverage(compliance_status, attestations),
        critical_findings=critical_findings.build_critical_findings(evidence),
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
    attestations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute readiness across all 110 NIST 800-171r2 requirements.

    Unmeasured requirements (those with no internal control mapping) count
    as NOT_ADDRESSED unless manually attested. Attestations fill in
    unmeasured items; automated signal wins when both exist.
    """
    coverage_report = coverage.compute_coverage(compliance_status, attestations)
    total = coverage_report["totalRequirements"]

    # Aggregate effective status per requirement.
    compliant = partial = not_addressed = 0
    family_rows: list[dict[str, Any]] = []
    for family in coverage_report["families"]:
        fam_compliant = fam_partial = fam_not = 0
        for req in family["requirements"]:
            status = req.get("effectiveStatus") or "NOT_ADDRESSED"
            if status == "COMPLIANT":
                fam_compliant += 1
                compliant += 1
            elif status == "PARTIAL":
                fam_partial += 1
                partial += 1
            else:
                fam_not += 1
                not_addressed += 1
        fam_total = len(family["requirements"]) or 1
        fam_pct = round(((fam_compliant + fam_partial * 0.5) / fam_total) * 100)
        family_rows.append(
            {
                "key": family["key"],
                "title": family["title"],
                "total": len(family["requirements"]),
                "compliant": fam_compliant,
                "partial": fam_partial,
                "notAddressed": fam_not,
                "pct": fam_pct,
            }
        )
    family_rows.sort(key=lambda r: (r["pct"], r["key"]))

    percentage = round(((compliant + partial * 0.5) / total) * 100) if total else 0

    # Top gaps remain control-level (more actionable for IT staff).
    controls = compliance_status.get("controls", {}) or {}
    bucket_order = {"quick_win": 0, "medium": 1, "heavy_lift": 2}
    gaps: list[dict[str, Any]] = []
    for cid, control in controls.items():
        if control.get("status") == "COMPLIANT":
            continue
        remediation_info = control.get("remediation") or {}
        gaps.append(
            {
                "id": cid,
                "title": control.get("title"),
                "status": control.get("status"),
                "firstGap": (control.get("gaps") or [""])[0],
                "effort": remediation_info.get("effort", "Unknown"),
                "bucket": remediation_info.get("bucket", "medium"),
            }
        )
    gaps.sort(
        key=lambda g: (
            0 if g["status"] == "NOT_ADDRESSED" else 1,
            bucket_order.get(g["bucket"], 1),
        )
    )

    quick_win_count = sum(
        1 for tasks in (remediation.get("quick_win") or [])
        if tasks.get("status") != "COMPLIANT"
    )

    # Automated maturity is still a control-level signal.
    summary = compliance_status.get("summary", {}) or {}
    return {
        "total": total,
        "compliant": compliant,
        "partial": partial,
        "notAddressed": not_addressed,
        "automatedMaturity": summary.get("automatedMaturity", 0),
        "percentage": percentage,
        "quickWins": quick_win_count,
        "familyRows": family_rows,
        "topGaps": gaps[:5],
        "controlsMeasured": len(controls),
        "requirementsWithoutEvidence": coverage_report["summary"]["not_measured"],
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
    attestations = attestations_store.load()
    remediation = generate_remediation_backlog(compliance_status)
    html = generate_report(compliance_status, evidence, attestations=attestations)
    outputs = write_outputs(
        evidence,
        compliance_status,
        remediation,
        html,
        output_dir,
    )
    readiness = _build_readiness(compliance_status, remediation, attestations)
    try:
        history.archive_run(
            output_dir, evidence, compliance_status, remediation, html, readiness
        )
    except Exception as exc:
        logger.warning("failed to archive run: %s", exc)
    retention_days = ((config.get("reporting") or {}).get("history_retention_days")) or 365
    try:
        history.prune_runs(output_dir, keep_days=int(retention_days))
    except Exception as exc:
        logger.warning("failed to prune history: %s", exc)
    return {
        "outputs": outputs,
        "summary": compliance_status.get("summary", {}),
        "readiness": readiness,
        "collection_warnings": evidence["collection_warnings"],
    }


def main(argv: list[str] | None = None) -> int:
    import sys
    raw_argv = list(argv) if argv is not None else sys.argv[1:]

    # Pre-scan for an explicit subcommand. If none, treat as the legacy
    # "run" invocation (--config / --output at the top level).
    known_commands = {"run", "bootstrap"}
    command = "run"
    subcommand_argv: list[str] = raw_argv
    for idx, token in enumerate(raw_argv):
        if token in known_commands:
            command = token
            subcommand_argv = raw_argv[:idx] + raw_argv[idx + 1:]
            break

    if command == "bootstrap":
        parser = argparse.ArgumentParser(
            prog="cmmc-gcc-collector bootstrap",
            description="Create the Entra app registration via device-code OAuth (interactive).",
        )
    else:
        parser = argparse.ArgumentParser(
            prog="cmmc-gcc-collector",
            description="Collect CMMC pre-assessment evidence from a GCC-High tenant.",
        )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("CMMC_LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    if command == "bootstrap":
        parser.add_argument("--tenant", required=True)
        parser.add_argument("--config", default="./config.json")
        parser.add_argument("--display-name", default="cmmc-gcc-evidence-collector")
        parser.add_argument("--secret-ttl-days", type=int, default=180)
    else:
        parser.add_argument("--config", required=True)
        parser.add_argument("--output", default="./reports")

    args = parser.parse_args(subcommand_argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if command == "bootstrap":
        return _bootstrap_command(args)
    return _run_command(args)


def _run_command(args) -> int:
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


def _bootstrap_command(args) -> int:
    import bootstrap
    try:
        result = bootstrap.bootstrap_app(
            tenant_identifier=args.tenant,
            app_display_name=args.display_name,
            secret_ttl_days=args.secret_ttl_days,
        )
    except bootstrap.BootstrapError as exc:
        logger.error("Bootstrap failed: %s", exc)
        return 4

    config_path = Path(args.config)
    existing: dict[str, Any] = {}
    if config_path.exists():
        try:
            existing = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("Existing config.json was not valid JSON; starting fresh.")
            existing = {}
    existing["tenant_id"] = result["tenant_id"]
    existing["client_id"] = result["client_id"]
    existing.setdefault("authority", "https://login.microsoftonline.us")
    existing.setdefault("graph_base_url", "https://graph.microsoft.us/v1.0")
    existing.pop("client_secret", None)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    print("")
    print(f"App registered.")
    print(f"  Config updated: {config_path}")
    print(f"  Tenant ID:      {result['tenant_id']}")
    print(f"  Client ID:      {result['client_id']}")
    print(f"  Client Secret:  {result['client_secret']}")
    print("")
    print("Store the secret immediately — it cannot be retrieved again.")
    print("Export it for runs:  export CMMC_CLIENT_SECRET='...'")
    print("Or paste into the Flask web UI login on first visit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
