import json

from typer.testing import CliRunner

from vtx_detection_lab.engine.evaluator import evaluate_telemetry
from vtx_detection_lab.main import app
from vtx_detection_lab.models import LogSource, TelemetryEvent
from vtx_detection_lab.parsers.rule_loader import load_rules_from_dir
from vtx_detection_lab.reporting.markdown_renderer import render_detection_report

runner = CliRunner()


def test_cli_validate_succeeds_for_project_catalog():
    result = runner.invoke(app, ["validate"])

    assert result.exit_code == 0
    assert "4 regras YAML" in result.stdout
    assert "4 regras Wazuh" in result.stdout


def test_cli_replay_e2e_generates_markdown_report_and_passes_strict_gate(tmp_path):
    output_file = tmp_path / "reports" / "replay.md"

    result = runner.invoke(
        app,
        [
            "replay",
            "--telemetry",
            "telemetry/fixtures/atomic_replay_events.json",
            "--output",
            str(output_file),
            "--strict",
        ],
    )

    assert result.exit_code == 0
    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")
    assert "PASS (0 FP / 0 FN)" in content
    assert "**100.0%**" in content
    for technique in ("T1059.001", "T1003.001", "T1053.005", "T1110.001"):
        assert technique in content
    for sid in ("100101", "100102", "100103", "100104"):
        assert sid in content


def test_cli_replay_strict_fails_when_false_negative_occurs(tmp_path):
    bad_events = [
        {
            "event_id": "EVT-MISSED",
            "timestamp": "2026-11-25T13:00:00Z",
            "host": "FIN-WKSTN-01",
            "log_source": "sysmon",
            "expected_rule_id": "VTX-1001",
            "payload": {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -Command Get-Process",
            },
        }
    ]
    telemetry_file = tmp_path / "bad_events.json"
    telemetry_file.write_text(json.dumps(bad_events), encoding="utf-8")
    output_file = tmp_path / "failed_report.md"

    result = runner.invoke(
        app,
        [
            "replay",
            "--telemetry",
            str(telemetry_file),
            "--output",
            str(output_file),
            "--strict",
        ],
    )

    assert result.exit_code == 1
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "FAIL" in content
    assert "EVT-MISSED" in content


def test_render_report_highlights_false_positives():
    rules = load_rules_from_dir("rules/sigma_lite")
    fp_event = TelemetryEvent(
        event_id="EVT-FP-99",
        timestamp="2026-11-25T13:05:00Z",
        host="CDE-APP-WIN-01",
        log_source=LogSource.SYSMON,
        expected_rule_id=None,
        payload={
            "EventID": "1",
            "Image": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "schtasks.exe /create /tn DailyJob /tr calc.exe /sc daily",
        },
    )

    summary = evaluate_telemetry([fp_event], rules)
    markdown = render_detection_report(rules, summary)

    assert "FAIL" in markdown
    assert "EVT-FP-99" in markdown
    assert "VTX-1003" in markdown
