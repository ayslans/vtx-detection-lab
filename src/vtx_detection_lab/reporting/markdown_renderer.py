from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from vtx_detection_lab.engine.evaluator import ReplaySummary
from vtx_detection_lab.models import DetectionRule, Severity

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _format_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _sanitize_cell(value: object, max_len: int = 90) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ").strip()
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def render_detection_report(
    rules: list[DetectionRule],
    summary: ReplaySummary,
    wazuh_rules: list[dict[str, str]] | None = None,
) -> str:
    """Renderiza boletim técnico e executivo de validação Detection-as-Code em Markdown."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    gate_passed = summary.false_positives == 0 and summary.false_negatives == 0
    gate_status = "PASS (0 FP / 0 FN)" if gate_passed else "FAIL (Revisão Necessária)"

    wazuh_by_mitre = {
        item["mitre_technique"]: item["id"]
        for item in (wazuh_rules or [])
        if item.get("mitre_technique")
    }

    sorted_rules = sorted(
        rules,
        key=lambda r: (SEVERITY_ORDER.get(r.severity, 99), r.rule_id),
    )
    sorted_alerts = sorted(
        summary.alerts,
        key=lambda a: (SEVERITY_ORDER.get(a.severity, 99), a.timestamp, a.event_id),
    )

    lines: list[str] = [
        "# Relatório de Validação Detection-as-Code — vtx-detection-lab",
        "",
        f"- **Gerado em:** {generated_at}",
        f"- **Regras avaliadas:** {len(rules)}",
        f"- **Eventos de telemetria:** {summary.total_events}",
        f"- **Status do Quality Gate:** `{gate_status}`",
        "",
        "## 1. Resumo Executivo e Métricas de Precisão",
        "",
        "| Métrica | Valor |",
        "| :--- | :---: |",
        f"| **Total de Eventos Reproduzidos** | {summary.total_events} |",
        f"| **Alertas Disparados** | {summary.total_alerts} |",
        f"| **True Positives (TP)** | {summary.true_positives} |",
        f"| **True Negatives (TN)** | {summary.true_negatives} |",
        f"| **False Positives (FP)** | {summary.false_positives} |",
        f"| **False Negatives (FN)** | {summary.false_negatives} |",
        f"| **Precision** | **{_format_pct(summary.precision)}** |",
        f"| **Recall** | **{_format_pct(summary.recall)}** |",
        "",
        "## 2. Matriz de Cobertura MITRE ATT&CK",
        "",
        "| Rule ID | Título | Severidade | Tática | Técnica MITRE | Fonte | Wazuh SID | Compliance |",
        "| :--- | :--- | :---: | :--- | :---: | :---: | :---: | :--- |",
    ]

    for rule in sorted_rules:
        wazuh_sid = wazuh_by_mitre.get(rule.mitre_technique, "N/A")
        refs = ", ".join(rule.pci_dss_refs + rule.nist_csf_refs) or "N/A"
        lines.append(
            f"| `{rule.rule_id}` | {_sanitize_cell(rule.title)} | **{rule.severity.value}** "
            f"| {_sanitize_cell(rule.mitre_tactic)} | `{rule.mitre_technique}` "
            f"| `{rule.log_source.value}` | `{wazuh_sid}` | {_sanitize_cell(refs)} |"
        )

    lines.extend(
        [
            "",
            "## 3. Alertas Disparados no Replay",
            "",
        ]
    )

    if not sorted_alerts:
        lines.append("Nenhum alerta disparado para o conjunto de eventos fornecido.")
    else:
        lines.extend(
            [
                "| Timestamp | Event ID | Host | Rule ID | Severidade | Técnica MITRE | Evidência (Matched Fields) |",
                "| :--- | :--- | :--- | :---: | :---: | :---: | :--- |",
            ]
        )
        for alert in sorted_alerts:
            fields_preview = "; ".join(
                f"{k}={v}" for k, v in alert.matched_fields.items()
            )
            lines.append(
                f"| `{alert.timestamp}` | `{alert.event_id}` | `{alert.host}` "
                f"| `{alert.rule_id}` | **{alert.severity.value}** "
                f"| `{alert.mitre_technique}` | {_sanitize_cell(fields_preview, max_len=110)} |"
            )

    lines.extend(
        [
            "",
            "## 4. Auditoria de Desvios (False Positives & False Negatives)",
            "",
        ]
    )

    if gate_passed:
        lines.append(
            "Nenhum falso positivo ou falso negativo registrado. Todas as regras passaram nos cenários de ataque simulado e controle benigno."
        )
    else:
        if summary.missed_event_ids:
            missed = ", ".join(f"`{eid}`" for eid in summary.missed_event_ids)
            lines.append(f"- **Eventos não detectados (False Negatives):** {missed}")
        if summary.unexpected_alerts:
            unexpected = ", ".join(
                f"`{a.event_id}` -> `{a.rule_id}`" for a in summary.unexpected_alerts
            )
            lines.append(f"- **Alertas inesperados (False Positives):** {unexpected}")

    lines.extend(
        [
            "",
            "## 5. Rastreabilidade de Governança",
            "",
            "- **PCI-DSS v4.0:** Req. 8.3 (Autenticação e controle de credenciais), Req. 10.2 (Registro e monitoramento de logs), Req. 11.5 (Detecção de intrusão e alterações).",
            "- **NIST CSF 2.0:** `DE.CM-01`, `DE.CM-03`, `DE.CM-09` (Monitoramento Contínuo) e `DE.AE-02`, `DE.AE-03` (Análise de Eventos Adversos).",
            "- **CIS Controls v8:** Control 8 (Audit Log Management) e Control 13 (Network Monitoring and Defense).",
            "",
        ]
    )

    return "\n".join(lines)


def save_markdown_report(content: str, output_path: str | Path) -> Path:
    """Persiste o relatório Markdown garantindo a criação de diretórios pai."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
