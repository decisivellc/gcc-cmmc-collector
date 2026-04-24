"""Flask web app for the CMMC GCC-High evidence collector.

Wraps ``main.run_pipeline`` so the operator can configure, run, and review
reports from a browser rather than the CLI. Secret handling is session-only:
the GCC-High ``client_secret`` is held in an in-memory store keyed by the
Flask session id and never written to disk. Restart the process to wipe all
secrets.
"""

from __future__ import annotations

import json
import logging
import os
import secrets as secrets_lib
import sys
import uuid
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attestations as attestations_store  # noqa: E402
import main as collector_main  # noqa: E402
from mappers import coverage as coverage_mod  # noqa: E402

logger = logging.getLogger("cmmc.web")

CONFIG_PATH = Path(os.environ.get("CMMC_CONFIG_PATH", ROOT / "config.json"))
REPORTS_DIR = Path(os.environ.get("CMMC_OUTPUT_DIR", ROOT / "reports"))
SESSION_SECRETS: dict[str, str] = {}

PUBLIC_CONFIG_FIELDS = {
    "tenant_id",
    "client_id",
    "authority",
    "graph_base_url",
    "reporting",
    "collectors",
    "schedule",
}


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets_lib.token_hex(32)
    if os.environ.get("CMMC_DEV") == "1":
        app.config["TEMPLATES_AUTO_RELOAD"] = True
        app.jinja_env.auto_reload = True
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    @app.before_request
    def _ensure_session_id() -> None:
        if "sid" not in session:
            session["sid"] = uuid.uuid4().hex

    @app.route("/")
    def index():
        cfg = _load_config_safe()
        if not _session_secret() or not _credentials_set(cfg):
            return redirect(url_for("login"))
        latest = _latest_run_info()
        return render_template(
            "dashboard.html",
            config=cfg,
            latest=latest,
            public_fields=PUBLIC_CONFIG_FIELDS,
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        cfg = _load_config_safe()
        if request.method == "POST":
            tenant_id = (request.form.get("tenant_id") or "").strip()
            client_id = (request.form.get("client_id") or "").strip()
            client_secret = request.form.get("client_secret") or ""
            if not tenant_id or not client_id or not client_secret:
                flash("All three fields are required.", "error")
                return render_template("login.html", config=cfg)
            cfg["tenant_id"] = tenant_id
            cfg["client_id"] = client_id
            cfg.setdefault("authority", "https://login.microsoftonline.us")
            cfg.setdefault("graph_base_url", "https://graph.microsoft.us/v1.0")
            cfg.setdefault("collectors", _default_collectors())
            cfg.pop("client_secret", None)
            _save_config(cfg)
            SESSION_SECRETS[session["sid"]] = client_secret
            flash("Credentials accepted. Secret held in memory for this session.", "ok")
            return redirect(url_for("index"))
        return render_template("login.html", config=cfg)

    @app.route("/logout", methods=["POST"])
    def logout():
        SESSION_SECRETS.pop(session.get("sid", ""), None)
        session.clear()
        flash("Session wiped. Re-enter your client secret to continue.", "ok")
        return redirect(url_for("login"))

    @app.route("/config", methods=["GET", "POST"])
    def config_view():
        cfg = _load_config_safe()
        if request.method == "POST":
            collectors_cfg = cfg.setdefault("collectors", _default_collectors())
            for name in ("azure_ad", "intune", "defender", "exchange", "email_security", "policies"):
                block = collectors_cfg.setdefault(name, {})
                block["enabled"] = request.form.get(f"{name}_enabled") == "on"
            policies = collectors_cfg.setdefault("policies", {})
            policies["site_url"] = (request.form.get("policies_site_url") or "").strip()
            raw_bg = request.form.get("break_glass_upns") or ""
            upns = [line.strip() for line in raw_bg.splitlines() if line.strip()]
            cfg.setdefault("exceptions", {})["break_glass_upns"] = upns
            _save_config(cfg)
            flash("Configuration saved.", "ok")
            return redirect(url_for("config_view"))
        return render_template("config.html", config=cfg)

    @app.route("/run", methods=["POST"])
    def run():
        secret = _session_secret()
        cfg = _load_config_safe()
        if not secret or not _credentials_set(cfg):
            flash("Log in with your tenant credentials first.", "error")
            return redirect(url_for("login"))
        runnable_cfg = dict(cfg)
        runnable_cfg["client_secret"] = secret
        try:
            result = collector_main.run_pipeline(runnable_cfg, REPORTS_DIR)
        except Exception as exc:
            logger.exception("Pipeline run failed")
            flash(f"Run failed: {exc}", "error")
            return redirect(url_for("index"))
        readiness = result.get("readiness", {})
        warnings = result.get("collection_warnings") or []
        flash(
            f"Run complete. {readiness.get('compliant', 0)} of {readiness.get('total', 0)} "
            f"controls compliant ({readiness.get('percentage', 0)}%). "
            f"{len(warnings)} collection warning(s).",
            "ok",
        )
        return redirect(url_for("report"))

    @app.route("/report")
    def report():
        report_path = REPORTS_DIR / "compliance-report.html"
        if not report_path.exists():
            flash("No report generated yet. Click 'Run now' first.", "error")
            return redirect(url_for("index"))
        return render_template("report.html")

    @app.route("/attestations", methods=["GET"])
    def attestations_view():
        cfg = _load_config_safe()
        if not _session_secret() or not _credentials_set(cfg):
            return redirect(url_for("login"))
        all_rows = _attestation_rows()
        unmeasured_rows = [r for r in all_rows if r["coverageLevel"] == "not_measured"]
        attested_rows = [r for r in unmeasured_rows if r["attestation"]]
        needs_rows = [r for r in unmeasured_rows if not r["attestation"]]
        filter_level = request.args.get("filter", "needs")
        if filter_level == "needs":
            rows = needs_rows
        elif filter_level == "attested":
            rows = attested_rows
        elif filter_level == "all_unmeasured":
            rows = unmeasured_rows
        else:
            filter_level = "needs"
            rows = needs_rows
        return render_template(
            "attestations.html",
            rows=rows,
            filter_level=filter_level,
            unmeasured_total=len(unmeasured_rows),
            attested_count=len(attested_rows),
            needs_count=len(needs_rows),
        )

    @app.route("/attestations/<req_id>", methods=["POST"])
    def attestation_save(req_id: str):
        if not _session_secret() or not _credentials_set(_load_config_safe()):
            return redirect(url_for("login"))
        action = request.form.get("action", "save")
        if action == "delete":
            attestations_store.remove(req_id)
            flash(f"Attestation for {req_id} removed.", "ok")
            return redirect(url_for("attestations_view"))
        status = (request.form.get("status") or "").strip()
        rationale = (request.form.get("rationale") or "").strip()
        review_by = (request.form.get("review_by") or "").strip() or None
        if status not in attestations_store.VALID_STATUSES:
            flash("Invalid status.", "error")
            return redirect(url_for("attestations_view"))
        if len(rationale) < 15:
            flash("Rationale is too short — describe how the requirement is met.", "error")
            return redirect(url_for("attestations_view"))
        attestations_store.upsert(
            req_id,
            status=status,
            rationale=rationale,
            attested_by=_attesting_user(cfg=_load_config_safe()),
            review_by=review_by,
        )
        flash(f"Attestation for {req_id} saved.", "ok")
        return redirect(url_for("attestations_view", filter=request.args.get("filter", "unmeasured")))

    @app.route("/reports/<path:filename>")
    def report_file(filename: str):
        safe_dir = REPORTS_DIR.resolve()
        target = (safe_dir / filename).resolve()
        if not str(target).startswith(str(safe_dir)):
            abort(404)
        if not target.exists():
            abort(404)
        return send_from_directory(safe_dir, filename)

    return app


def _load_config_safe() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {"collectors": _default_collectors()}
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except json.JSONDecodeError:
        logger.warning("config.json is not valid JSON; starting with defaults.")
        return {"collectors": _default_collectors()}
    cfg.setdefault("collectors", _default_collectors())
    cfg.pop("client_secret", None)
    return cfg


def _save_config(cfg: dict[str, Any]) -> None:
    safe = {k: v for k, v in cfg.items() if k != "client_secret"}
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CONFIG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(safe, fh, indent=2)


def _credentials_set(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("tenant_id")) and bool(cfg.get("client_id"))


def _session_secret() -> str | None:
    return SESSION_SECRETS.get(session.get("sid", ""))


def _attesting_user(cfg: dict[str, Any]) -> str:
    """Best-effort UPN for who is making the attestation.

    We don't currently collect the operator's own UPN (login is
    app-registration credentials, not the human's). Fall back to a generic
    label that makes clear who committed — the `attestedAt` timestamp keeps
    the record auditable regardless.
    """
    return (cfg.get("attestor_upn") or "operator@local").strip()


def _attestation_rows() -> list[dict[str, Any]]:
    """Flatten the 110 requirements into a list suitable for the attestation page."""
    records = attestations_store.load()
    cov = coverage_mod.compute_coverage({"controls": {}}, records)
    rows: list[dict[str, Any]] = []
    for family in cov["families"]:
        for req in family["requirements"]:
            rows.append({**req, "family": family["key"], "familyTitle": family["title"]})
    return rows


def _default_collectors() -> dict[str, Any]:
    return {
        "azure_ad": {"enabled": True, "inactivity_threshold_days": 30},
        "intune": {"enabled": True, "device_sync_threshold_days": 30, "filter_os": ""},
        "defender": {"enabled": True, "vulnerability_threshold_severity": "high"},
        "exchange": {"enabled": True},
        "email_security": {"enabled": True, "domains": []},
        "policies": {"enabled": True, "site_url": ""},
    }


def _latest_run_info() -> dict[str, Any] | None:
    report_path = REPORTS_DIR / "compliance-report.html"
    evidence_path = REPORTS_DIR / "evidence.json"
    if not report_path.exists():
        return None
    info: dict[str, Any] = {
        "report_mtime": report_path.stat().st_mtime,
    }
    if evidence_path.exists():
        try:
            with evidence_path.open("r", encoding="utf-8") as fh:
                evidence = json.load(fh)
            info["collected_at"] = evidence.get("collected_at")
            info["warnings"] = len(evidence.get("collection_warnings") or [])
        except json.JSONDecodeError:
            pass
    return info


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    dev_mode = os.environ.get("CMMC_DEV") == "1"
    app = create_app()
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        debug=dev_mode,
        use_reloader=dev_mode,
    )
