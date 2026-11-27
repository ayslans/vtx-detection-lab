from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from vtx_detection_lab.assets import (
    UNKNOWN_ASSET_ID,
    AssetInventory,
    load_asset_inventory,
)
from vtx_detection_lab.engine.evaluator import (
    evaluate_telemetry,
    load_telemetry_events,
    save_alerts_jsonl,
)
from vtx_detection_lab.parsers.rule_loader import (
    load_rules_from_dir,
    parse_wazuh_rules_xml,
)
from vtx_detection_lab.reporting.markdown_renderer import (
    render_detection_report,
    save_markdown_report,
)

app = typer.Typer(
    help="vtx-detection-lab — Detection-as-Code validation, MITRE ATT&CK coverage and telemetry replay CLI."
)
console = Console()


@app.command("validate")
def validate_catalog(
    rules_dir: Path = typer.Option(
        Path("rules/sigma_lite"),
        "--rules-dir",
        help="Diretório com regras YAML Detection-as-Code.",
    ),
    wazuh_xml: Path = typer.Option(
        Path("rules/wazuh/local_rules.xml"),
        "--wazuh-xml",
        help="Arquivo XML de regras customizadas do Wazuh.",
    ),
) -> None:
    """Valida sintaxe das regras YAML, integridade do XML Wazuh e alinhamento MITRE ATT&CK."""
    yaml_rules = load_rules_from_dir(rules_dir)
    wazuh_rules = parse_wazuh_rules_xml(wazuh_xml)

    yaml_mitre = {r.mitre_technique for r in yaml_rules}
    wazuh_mitre = {r["mitre_technique"] for r in wazuh_rules if r.get("mitre_technique")}

    missing_in_wazuh = sorted(yaml_mitre - wazuh_mitre)
    missing_in_yaml = sorted(wazuh_mitre - yaml_mitre)

    if missing_in_wazuh or missing_in_yaml:
        console.print("[bold red]Falha de alinhamento MITRE ATT&CK entre YAML e Wazuh XML.[/bold red]")
        if missing_in_wazuh:
            console.print(f"Ausentes no Wazuh XML: {', '.join(missing_in_wazuh)}")
        if missing_in_yaml:
            console.print(f"Ausentes no catálogo YAML: {', '.join(missing_in_yaml)}")
        raise typer.Exit(code=1)

    console.print(
        f"[bold green]Catálogo válido:[/bold green] {len(yaml_rules)} regras YAML e "
        f"{len(wazuh_rules)} regras Wazuh alinhadas em {len(yaml_mitre)} técnicas MITRE ATT&CK."
    )


@app.command("replay")
def replay_telemetry(
    telemetry: Path = typer.Option(
        Path("telemetry/fixtures/atomic_replay_events.json"),
        "--telemetry",
        "-t",
        help="Arquivo .json ou .jsonl com eventos de telemetria simulada.",
    ),
    rules_dir: Path = typer.Option(
        Path("rules/sigma_lite"),
        "--rules-dir",
        help="Diretório com regras YAML Detection-as-Code.",
    ),
    wazuh_xml: Path = typer.Option(
        Path("rules/wazuh/local_rules.xml"),
        "--wazuh-xml",
        help="Arquivo XML de regras Wazuh para cruzamento de SID na matriz.",
    ),
    output: Path = typer.Option(
        Path("docs/evidence/atomic_replay_report.md"),
        "--output",
        "-o",
        help="Caminho de saída do relatório Markdown.",
    ),
    assets: Optional[Path] = typer.Option(
        None,
        "--assets",
        "-a",
        help="Catálogo YAML de inventário para mapear host -> asset_id (ex: examples/assets.yaml).",
    ),
    alerts_jsonl: Optional[Path] = typer.Option(
        None,
        "--alerts-jsonl",
        help="Caminho opcional para exportar alertas disparados em formato JSONL.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Retorna código de saída 1 se houver qualquer False Positive ou False Negative (CI/CD gate).",
    ),
) -> None:
    """Executa replay de telemetria contra as regras e gera o relatório de cobertura MITRE ATT&CK."""
    rules = load_rules_from_dir(rules_dir)
    wazuh_rules = parse_wazuh_rules_xml(wazuh_xml) if wazuh_xml.exists() else []
    events = load_telemetry_events(telemetry)

    inventory: Optional[AssetInventory] = None
    if assets is not None:
        try:
            inventory = load_asset_inventory(assets)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            console.print(
                f"[yellow]Aviso de inventário:[/yellow] falha ao carregar '{assets}' ({exc}); "
                f"aplicando fallback '{UNKNOWN_ASSET_ID}'."
            )

    summary = evaluate_telemetry(events, rules, asset_inventory=inventory)
    report_md = render_detection_report(rules, summary, wazuh_rules=wazuh_rules)
    saved_path = save_markdown_report(report_md, output)

    if alerts_jsonl is not None:
        saved_jsonl = save_alerts_jsonl(summary.alerts, alerts_jsonl)
        console.print(f"[green]Alertas JSONL exportados em:[/green] {saved_jsonl}")

    table = Table(title="vtx-detection-lab — Replay Summary")
    table.add_column("Métrica", style="cyan")
    table.add_column("Resultado", justify="right", style="bold")
    table.add_row("Eventos analisados", str(summary.total_events))
    table.add_row("Alertas disparados", str(summary.total_alerts))
    table.add_row("True Positives (TP)", str(summary.true_positives))
    table.add_row("True Negatives (TN)", str(summary.true_negatives))
    table.add_row("False Positives (FP)", str(summary.false_positives))
    table.add_row("False Negatives (FN)", str(summary.false_negatives))
    table.add_row("Precision", f"{summary.precision * 100:.1f}%")
    table.add_row("Recall", f"{summary.recall * 100:.1f}%")
    console.print(table)
    console.print(f"[green]Relatório salvo em:[/green] {saved_path}")

    if strict and (summary.false_positives > 0 or summary.false_negatives > 0):
        console.print("[bold red]Quality Gate reprovado (--strict): existem FPs ou FNs.[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
