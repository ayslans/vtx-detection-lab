import json

from vtx_detection_lab.engine.evaluator import (
    evaluate_event,
    evaluate_telemetry,
    load_telemetry_events,
)
from vtx_detection_lab.models import LogSource, TelemetryEvent
from vtx_detection_lab.parsers.rule_loader import load_rules_from_dir


def test_atomic_replay_achieves_perfect_precision_and_recall():
    rules = load_rules_from_dir("rules/sigma_lite")
    events = load_telemetry_events("telemetry/fixtures/atomic_replay_events.json")

    summary = evaluate_telemetry(events, rules)

    assert summary.total_events == 10
    assert summary.true_positives == 6
    assert summary.true_negatives == 4
    assert summary.false_positives == 0
    assert summary.false_negatives == 0
    assert summary.precision == 1.0
    assert summary.recall == 1.0


def test_evaluator_respects_log_source_boundary():
    rules = load_rules_from_dir("rules/sigma_lite")
    mismatched_event = TelemetryEvent(
        event_id="EVT-MISMATCH",
        timestamp="2026-11-25T11:00:00Z",
        host="PAY-LNX-GW-01",
        log_source=LogSource.LINUX_AUTH,
        payload={
            "EventID": "1",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -enc AAAA",
        },
    )

    alerts = evaluate_event(mismatched_event, rules)
    assert alerts == []


def test_evaluator_tracks_false_negatives():
    rules = load_rules_from_dir("rules/sigma_lite")
    missed_event = TelemetryEvent(
        event_id="EVT-FN",
        timestamp="2026-11-25T11:05:00Z",
        host="FIN-WKSTN-01",
        log_source=LogSource.SYSMON,
        expected_rule_id="VTX-1001",
        payload={
            "EventID": "1",
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -Command Get-Date",
        },
    )

    summary = evaluate_telemetry([missed_event], rules)
    assert summary.false_negatives == 1
    assert summary.missed_event_ids == ["EVT-FN"]
    assert summary.recall == 0.0


def test_evaluator_tracks_false_positives_on_benign_event():
    rules = load_rules_from_dir("rules/sigma_lite")
    unexpected_fp = TelemetryEvent(
        event_id="EVT-FP",
        timestamp="2026-11-25T11:10:00Z",
        host="FIN-WKSTN-01",
        log_source=LogSource.SYSMON,
        expected_rule_id=None,
        payload={
            "EventID": "1",
            "Image": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "schtasks.exe /create /tn Backup /tr C:\\backup.bat /sc daily",
        },
    )

    summary = evaluate_telemetry([unexpected_fp], rules)
    assert summary.false_positives == 1
    assert summary.true_negatives == 0
    assert summary.unexpected_alerts[0].rule_id == "VTX-1003"


def test_load_telemetry_supports_jsonl(tmp_path):
    jsonl_file = tmp_path / "events.jsonl"
    record = {
        "event_id": "EVT-JSONL-1",
        "timestamp": "2026-11-25T12:00:00Z",
        "host": "PAY-LNX-GW-01",
        "log_source": "linux_auth",
        "expected_rule_id": "VTX-1004",
        "payload": {
            "service": "sshd",
            "message": "Failed password for root from 203.0.113.99 port 2222 ssh2",
        },
    }
    jsonl_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

    events = load_telemetry_events(jsonl_file)
    assert len(events) == 1
    assert events[0].event_id == "EVT-JSONL-1"
