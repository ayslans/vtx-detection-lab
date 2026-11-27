from pathlib import Path

from typer.testing import CliRunner

from vtx_detection_lab.assets import UNKNOWN_ASSET_ID, load_asset_inventory
from vtx_detection_lab.engine.evaluator import load_telemetry_events
from vtx_detection_lab.main import app
from vtx_detection_lab.models import LogSource
from vtx_detection_lab.parsers.log_normalizer import NormalizeSource, normalize_log_file

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_ASSETS = REPO_ROOT / "examples" / "assets.yaml"
SAMPLE_NGINX = REPO_ROOT / "telemetry" / "fixtures" / "sample_nginx.log"
SAMPLE_FASTAPI = REPO_ROOT / "telemetry" / "fixtures" / "sample_fastapi.log"

runner = CliRunner()


def test_normalize_nginx_combined_resolves_asset_id_and_uri() -> None:
    inv = load_asset_inventory(EXAMPLES_ASSETS)
    res = normalize_log_file(
        SAMPLE_NGINX,
        source=NormalizeSource.AUTO,
        host="PAY-LNX-GW-01",
        asset_inventory=inv,
    )

    assert res.total_lines == 2
    assert res.parsed_lines == 2
    assert res.skipped_lines == 0

    first = res.events[0]
    assert first.log_source == LogSource.NGINX
    assert first.asset_id == "pay-lnx-gw-01"
    assert first.timestamp == "2026-11-27T04:10:12Z"
    assert first.payload["src_ip"] == "203.0.113.42"
    assert first.payload["http_path"] == "/api/v1/payments"
    assert first.payload["query_string"] == "id=1%20UNION%20SELECT%201"
    assert first.payload["http_status"] == 403
    assert first.payload["user_agent"] == "sqlmap/1.8"


def test_normalize_fastapi_text_and_json_lines() -> None:
    inv = load_asset_inventory(EXAMPLES_ASSETS)
    res = normalize_log_file(
        SAMPLE_FASTAPI,
        source=NormalizeSource.AUTO,
        host="PAY-LNX-GW-01",
        asset_inventory=inv,
    )

    assert res.parsed_lines == 2
    assert res.skipped_lines == 0
    assert all(e.log_source == LogSource.FASTAPI for e in res.events)
    assert all(e.asset_id == "pay-lnx-gw-01" for e in res.events)
    assert res.events[0].payload["src_ip"] == "198.51.100.7"
    assert res.events[1].payload["user_agent"] == "python-httpx/0.27.2"


def test_cli_normalize_generates_replay_compatible_jsonl(tmp_path: Path) -> None:
    out_jsonl = tmp_path / "nginx_events.jsonl"
    result = runner.invoke(
        app,
        [
            "normalize",
            "--input",
            str(SAMPLE_NGINX),
            "--source",
            "auto",
            "--host",
            "PAY-LNX-GW-01",
            "--assets",
            str(EXAMPLES_ASSETS),
            "--output",
            str(out_jsonl),
            "--strict",
        ],
    )

    assert result.exit_code == 0, result.output
    loaded = load_telemetry_events(out_jsonl)
    assert len(loaded) == 2
    assert loaded[0].log_source == LogSource.NGINX
    assert loaded[0].asset_id == "pay-lnx-gw-01"


def test_cli_normalize_strict_fails_on_malformed_line(tmp_path: Path) -> None:
    bad_log = tmp_path / "bad.log"
    bad_log.write_text("linha invalida sem formato http\n", encoding="utf-8")
    out_jsonl = tmp_path / "out.jsonl"

    result = runner.invoke(
        app,
        [
            "normalize",
            "--input",
            str(bad_log),
            "--output",
            str(out_jsonl),
            "--strict",
        ],
    )

    assert result.exit_code == 1


def test_normalize_unknown_host_uses_fallback_asset_id(tmp_path: Path) -> None:
    res = normalize_log_file(
        SAMPLE_NGINX,
        source=NormalizeSource.NGINX,
        host="HOST-NAO-CADASTRADO",
        asset_inventory=load_asset_inventory(EXAMPLES_ASSETS),
    )
    assert all(e.asset_id == UNKNOWN_ASSET_ID for e in res.events)
