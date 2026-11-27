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
from vtx_detection_lab.correlator import (
    correlate_ti_and_triage,
    save_correlation_report,
)
from vtx_detection_lab.engine.evaluator import (
    evaluate_telemetry,
    load_telemetry_events,
    save_alerts_jsonl,
)
from vtx_detection_lab.parsers.log_normalizer import (
    NormalizeSource,
    normalize_log_file,
    save_telemetry_jsonl,
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


def _load_inventory_safe(assets: Optional[Path]) -> Optional[AssetInventory]:
    if assets is None:
        return None
    try:
        return load_asset_inventory(assets)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        console.print(
            f"[yellow]Aviso de inventário:[/yellow] falha ao carregar '{assets}' ({exc}); "
            f"aplicando fallback '{UNKNOWN_ASSET_ID}'."
        )
        return None


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


@app.command("normalize")
def normalize_logs(
    input_file: Path = typer.Option(
        ...,
        "--input",
        "-i",
        help="Arquivo de log bruto Nginx (Combined/JSON) ou FastAPI/Uvicorn (texto/JSON).",
    ),
    output: Path = typer.Option(
        Path("artifacts/normalized_events.jsonl"),
        "--output",
        "-o",
        help="Arquivo JSONL de saída compatível com o comando replay.",
    ),
    source: NormalizeSource = typer.Option(
        NormalizeSource.AUTO,
        "--source",
        "-s",
        help="Formato de origem (auto, nginx, fastapi).",
    ),
    host: str = typer.Option(
        "UNKNOWN-HOST",
        "--host",
        help="Hostname de origem para resolução de asset_id no inventário.",
    ),
    assets: Optional[Path] = typer.Option(
        None,
        "--assets",
        "-a",
        help="Catálogo YAML de inventário para mapear host -> asset_id.",
    ),
    asset_id: Optional[str] = typer.Option(
        None,
        "--asset-id",
        help="Sobrescreve o asset_id explicitamente (opcional).",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Retorna código de saída 1 se houver linhas não reconhecidas.",
    ),
) -> None:
    """Normaliza logs Nginx/FastAPI para TelemetryEvent JSONL com asset_id."""
    inventory = _load_inventory_safe(assets)
    result = normalize_log_file(
        input_path=input_file,
        source=source,
        host=host,
        asset_inventory=inventory,
        explicit_asset_id=asset_id,
    )
    saved = save_telemetry_jsonl(result.events, output)
    console.print(
        f"[green]Normalização concluída:[/green] {result.parsed_lines}/{result.total_lines} "
        f"linha(s) convertida(s) ({result.skipped_lines} ignorada(s)) -> {saved}"
    )

    if strict and result.skipped_lines > 0:
        console.print("[bold red]Modo --strict: existem linhas ignoradas no log.[/bold red]")
        raise typer.Exit(code=1)


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

    inventory = _load_inventory_safe(assets)
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


@app.command("correlate")
def correlate_assets(
    ti_input: list[Path] = typer.Option(
        ...,
        "--ti-input",
        help="Caminho(s) de saída JSON/JSONL do vtx-ti-enricher ou alertas com asset_id.",
    ),
    triage_input: list[Path] = typer.Option(
        ...,
        "--triage-input",
        help="Caminho(s) do contrato JSON (TriageJsonReport v1.0) do vtx-vuln-triage-ai.",
    ),
    output: Path = typer.Option(
        Path("artifacts/correlated_assets.json"),
        "--output",
        "-o",
        help="Caminho do relatório JSON consolidado por asset_id.",
    ),
    assets: Optional[Path] = typer.Option(
        None,
        "--assets",
        "-a",
        help="Catálogo YAML opcional de inventário para resolver hosts sem asset_id.",
    ),
    fail_on_corroborated: bool = typer.Option(
        False,
        "--fail-on-corroborated",
        help="Retorna código 1 se algum ativo tiver exposição corroborada (TI + vulnerabilidade).",
    ),
) -> None:
    """Consolida alertas enriquecidos (TI) e triagem de vulnerabilidades por asset_id."""
    inventory = _load_inventory_safe(assets)
    report = correlate_ti_and_triage(
        ti_paths=ti_input,
        triage_paths=triage_input,
        asset_inventory=inventory,
    )
    saved = save_correlation_report(report, output)

    table = Table(title="vtx-detection-lab — Asset Correlation Summary")
    table.add_column("Métrica", style="cyan")
    table.add_column("Resultado", justify="right", style="bold")
    table.add_row("Ativos consolidados", str(report.total_assets))
    table.add_row("Exposição corroborada (TI + Vuln)", str(report.corroborated_assets))
    table.add_row("Ativos CRITICAL", str(report.critical_assets))
    console.print(table)
    console.print(f"[green]Relatório consolidado salvo em:[/green] {saved}")

    if fail_on_corroborated and report.corroborated_assets > 0:
        console.print("[bold red]Exposição corroborada detectada em um ou mais ativos.[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
