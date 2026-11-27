import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from vtx_detection_lab.assets import (
    ASSET_ID_RE,
    UNKNOWN_ASSET_ID,
    AssetInventory,
    load_asset_inventory,
    resolve_asset_id,
)
from vtx_detection_lab.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_ASSETS = REPO_ROOT / "examples" / "assets.yaml"
FIXTURE_TELEMETRY = REPO_ROOT / "telemetry" / "fixtures" / "atomic_replay_events.json"

runner = CliRunner()


def test_load_example_inventory_and_resolve_hosts_case_insensitive() -> None:
    inv = load_asset_inventory(EXAMPLES_ASSETS)
    assert inv.version == "1"
    assert len(inv.assets) == 4

    assert resolve_asset_id("CDE-APP-WIN-01", inv) == "cde-app-win-01"
    assert resolve_asset_id("cde-app-win-01", inv) == "cde-app-win-01"
    assert resolve_asset_id("PAY-LNX-GW-01", inv) == "pay-lnx-gw-01"
    assert resolve_asset_id("HOST-DESCONHECIDO", inv) == UNKNOWN_ASSET_ID


def test_reject_duplicate_hosts_in_inventory() -> None:
    payload = {
        "version": "1",
        "assets": [
            {
                "asset_id": "svc-a",
                "name": "Service A",
                "owner": "sec@empresa.local",
                "environment": "prod",
                "exposure": "internal",
                "criticality": "high",
                "hosts": ["HOST-01"],
            },
            {
                "asset_id": "svc-b",
                "name": "Service B",
                "owner": "sec@empresa.local",
                "environment": "prod",
                "exposure": "internal",
                "criticality": "medium",
                "hosts": ["host-01"],
            },
        ],
    }
    with pytest.raises(ValidationError, match="Duplicate host mappings"):
        AssetInventory.model_validate(payload)


def test_cli_replay_exports_alerts_jsonl_with_standard_asset_ids(tmp_path: Path) -> None:
    md_out = tmp_path / "replay.md"
    jsonl_out = tmp_path / "alerts.jsonl"

    result = runner.invoke(
        app,
        [
            "replay",
            "--telemetry",
            str(FIXTURE_TELEMETRY),
            "--output",
            str(md_out),
            "--assets",
            str(EXAMPLES_ASSETS),
            "--alerts-jsonl",
            str(jsonl_out),
            "--strict",
        ],
    )

    assert result.exit_code == 0, result.output
    assert jsonl_out.exists()

    lines = [ln for ln in jsonl_out.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) > 0

    for line in lines:
        alert = json.loads(line)
        assert alert["source"] == "vtx-detection-lab"
        assert ASSET_ID_RE.match(alert["asset_id"])
        assert alert["asset_id"] != UNKNOWN_ASSET_ID
        assert isinstance(alert["event_payload"], dict)


def test_cli_replay_missing_assets_file_uses_unknown_asset_fallback(tmp_path: Path) -> None:
    md_out = tmp_path / "replay.md"
    jsonl_out = tmp_path / "alerts_fallback.jsonl"

    result = runner.invoke(
        app,
        [
            "replay",
            "--telemetry",
            str(FIXTURE_TELEMETRY),
            "--output",
            str(md_out),
            "--assets",
            str(tmp_path / "missing_assets.yaml"),
            "--alerts-jsonl",
            str(jsonl_out),
            "--strict",
        ],
    )

    assert result.exit_code == 0, result.output
    lines = [ln for ln in jsonl_out.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) > 0
    assert all(json.loads(ln)["asset_id"] == UNKNOWN_ASSET_ID for ln in lines)
