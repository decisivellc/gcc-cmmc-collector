"""Smoke tests for the Flask web app."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    monkeypatch.setenv("CMMC_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("CMMC_OUTPUT_DIR", str(reports_dir))
    monkeypatch.setenv("FLASK_SECRET_KEY", "test")

    # Reload web.app so the module-level constants pick up the env vars.
    import importlib
    import web.app as web_app
    importlib.reload(web_app)
    app = web_app.create_app()
    app.config.update(TESTING=True)
    return app


def test_unauthenticated_root_redirects_to_login(app):
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_page_renders(app):
    client = app.test_client()
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Sign in" in resp.data


def test_login_persists_ids_and_holds_secret_in_memory(app, tmp_path):
    client = app.test_client()
    resp = client.post(
        "/login",
        data={
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "client_id": "11111111-1111-1111-1111-111111111111",
            "client_secret": "super-secret",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    # config.json written, secret NOT in it.
    config_path = Path(os.environ["CMMC_CONFIG_PATH"])
    assert config_path.exists()
    saved = json.loads(config_path.read_text())
    assert saved["tenant_id"] == "00000000-0000-0000-0000-000000000000"
    assert "client_secret" not in saved
    # Dashboard should now be accessible.
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data


def test_run_without_session_secret_redirects(app):
    import web.app as web_app
    web_app.SESSION_SECRETS.clear()
    client = app.test_client()
    resp = client.post("/run", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_logout_wipes_secret(app):
    import web.app as web_app
    client = app.test_client()
    client.post(
        "/login",
        data={
            "tenant_id": "t",
            "client_id": "c",
            "client_secret": "super-secret",
        },
    )
    assert any(v == "super-secret" for v in web_app.SESSION_SECRETS.values())
    client.post("/logout")
    assert "super-secret" not in web_app.SESSION_SECRETS.values()
