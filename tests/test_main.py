"""End-to-end tests for the main orchestrator."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import main
from main import ConfigError


def _write_config(tmp_path: Path, **overrides) -> Path:
    body = {
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "client_id": "11111111-1111-1111-1111-111111111111",
        "client_secret": "s",
        "collectors": {
            "azure_ad": {"enabled": True},
            "intune": {"enabled": True},
            "defender": {"enabled": True},
            "exchange": {"enabled": True},
        },
    }
    body.update(overrides)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body))
    return path


def test_load_config_rejects_placeholders(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "tenant_id": "YOUR_TENANT_ID_HERE",
                "client_id": "YOUR_APP_ID_HERE",
                "client_secret": "YOUR_CLIENT_SECRET_HERE",
            }
        )
    )
    with pytest.raises(ConfigError):
        main.load_config(str(path))


def test_load_config_honors_env_secret(tmp_path: Path, monkeypatch) -> None:
    cfg_path = _write_config(tmp_path, client_secret="YOUR_CLIENT_SECRET_HERE")
    monkeypatch.setenv("CMMC_CLIENT_SECRET", "env-secret")
    cfg = main.load_config(str(cfg_path))
    assert cfg["client_secret"] == "env-secret"


def test_main_writes_all_outputs(tmp_path: Path, sample_evidence) -> None:
    cfg_path = _write_config(tmp_path)
    output = tmp_path / "reports"

    fake_client = MagicMock()

    def fake_collect(_client):
        fake_collect.counter += 1
        name = list(main.COLLECTOR_FUNCTIONS.keys())[fake_collect.counter - 1]
        return sample_evidence[name]

    fake_collect.counter = 0

    with patch.object(main, "authenticate", return_value=fake_client), patch.dict(
        main.COLLECTOR_FUNCTIONS,
        {name: (lambda c, n=name: sample_evidence[n]) for name in main.COLLECTOR_FUNCTIONS},
        clear=True,
    ):
        exit_code = main.main(["--config", str(cfg_path), "--output", str(output)])

    assert exit_code == 0
    assert (output / "compliance-report.html").exists()
    assert (output / "evidence.json").exists()
    assert (output / "remediation-backlog.json").exists()
    html = (output / "compliance-report.html").read_text()
    assert "CMMC Level 2 Readiness Report" in html
    assert "AC-2" in html


def test_main_returns_error_on_missing_config(tmp_path: Path) -> None:
    exit_code = main.main(
        ["--config", str(tmp_path / "does-not-exist.json"), "--output", str(tmp_path)]
    )
    assert exit_code == 2


def test_collector_failure_is_recorded(tmp_path: Path, sample_evidence) -> None:
    cfg_path = _write_config(tmp_path)
    output = tmp_path / "reports"
    fake_client = MagicMock()

    def failing_azure_ad(_client):
        raise RuntimeError("graph down")

    collectors = {name: (lambda c, n=name: sample_evidence[n]) for name in main.COLLECTOR_FUNCTIONS}
    collectors["azure_ad"] = failing_azure_ad

    with patch.object(main, "authenticate", return_value=fake_client), patch.dict(
        main.COLLECTOR_FUNCTIONS, collectors, clear=True
    ):
        exit_code = main.main(["--config", str(cfg_path), "--output", str(output)])

    assert exit_code == 0
    evidence = json.loads((output / "evidence.json").read_text())
    assert evidence["azure_ad"]["available"] is False
    assert "graph down" in evidence["azure_ad"]["error"]
