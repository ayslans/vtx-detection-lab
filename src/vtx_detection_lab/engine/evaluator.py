from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vtx_detection_lab.models import (
    AlertMatch,
    DetectionCondition,
    DetectionRule,
    TelemetryEvent,
)


class ReplaySummary(BaseModel):
    total_events: int
    total_alerts: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    alerts: list[AlertMatch] = Field(default_factory=list)
    missed_event_ids: list[str] = Field(default_factory=list)
    unexpected_alerts: list[AlertMatch] = Field(default_factory=list)


def load_telemetry_events(path: str | Path) -> list[TelemetryEvent]:
    """Carrega eventos de telemetria de arquivos .json (lista) ou .jsonl (1 evento por linha)."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Arquivo de telemetria não encontrado: {file_path}")

    raw_text = file_path.read_text(encoding="utf-8").strip()
    if not raw_text:
        return []

    if file_path.suffix.lower() == ".jsonl":
        items = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
    else:
        parsed = json.loads(raw_text)
        if not isinstance(parsed, list):
            raise ValueError(f"Esperada lista JSON de eventos em {file_path}.")
        items = parsed

    return [TelemetryEvent(**item) for item in items]


def _condition_matches(condition: DetectionCondition, payload: dict[str, Any]) -> bool:
    if condition.field not in payload or payload[condition.field] is None:
        return False

    value_str = str(payload[condition.field])
    value_lower = value_str.lower()

    if condition.equals is not None:
        if value_lower != condition.equals.lower():
            return False

    if condition.contains_any:
        if not any(token.lower() in value_lower for token in condition.contains_any):
            return False

    if condition.regex is not None:
        if re.search(condition.regex, value_str, flags=re.IGNORECASE) is None:
            return False

    return True


def evaluate_event(event: TelemetryEvent, rules: list[DetectionRule]) -> list[AlertMatch]:
    """Avalia um único evento de telemetria contra todas as regras do catálogo."""
    matches: list[AlertMatch] = []

    for rule in rules:
        if rule.log_source != event.log_source:
            continue

        if all(_condition_matches(cond, event.payload) for cond in rule.conditions):
            matched_fields = {
                cond.field: event.payload.get(cond.field)
                for cond in rule.conditions
                if cond.field in event.payload
            }
            matches.append(
                AlertMatch(
                    rule_id=rule.rule_id,
                    rule_title=rule.title,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    event_id=event.event_id,
                    host=event.host,
                    timestamp=event.timestamp,
                    matched_fields=matched_fields,
                )
            )

    return matches


def evaluate_telemetry(
    events: list[TelemetryEvent],
    rules: list[DetectionRule],
) -> ReplaySummary:
    """Executa replay completo calculando métricas de qualidade (TP, TN, FP, FN, Precision, Recall)."""
    all_alerts: list[AlertMatch] = []
    unexpected_alerts: list[AlertMatch] = []
    missed_event_ids: list[str] = []

    tp = tn = fp = fn = 0

    for event in events:
        event_alerts = evaluate_event(event, rules)
        all_alerts.extend(event_alerts)
        fired_ids = {alert.rule_id for alert in event_alerts}

        if event.expected_rule_id is not None:
            if event.expected_rule_id in fired_ids:
                tp += 1
            else:
                fn += 1
                missed_event_ids.append(event.event_id)

            for alert in event_alerts:
                if alert.rule_id != event.expected_rule_id:
                    fp += 1
                    unexpected_alerts.append(alert)
        else:
            if not event_alerts:
                tn += 1
            else:
                fp += len(event_alerts)
                unexpected_alerts.extend(event_alerts)

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0

    return ReplaySummary(
        total_events=len(events),
        total_alerts=len(all_alerts),
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        alerts=all_alerts,
        missed_event_ids=missed_event_ids,
        unexpected_alerts=unexpected_alerts,
    )
