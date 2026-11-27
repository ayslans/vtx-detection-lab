from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from vtx_detection_lab.assets import (
    ASSET_ID_RE,
    UNKNOWN_ASSET_ID,
    AssetInventory,
    resolve_asset_id,
)

RiskTier = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_VERDICT_RANK: dict[str, int] = {
    "unknown": 0,
    "benign": 1,
    "suspicious": 2,
    "malicious": 3,
}

_PRIORITY_RANK: dict[str, int] = {
    "P3": 1,
    "P2": 2,
    "P1": 3,
    "P0": 4,
}

_RISK_RANK: dict[RiskTier, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class ThreatIntelAssetSummary(BaseModel):
    highest_verdict: str = "unknown"
    alert_count: int = 0
    ioc_count: int = 0
    malicious_iocs: list[str] = Field(default_factory=list)
    suspicious_iocs: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence_entry_hashes: list[str] = Field(default_factory=list)


class VulnerabilityAssetSummary(BaseModel):
    finding_count: int = 0
    p0_count: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0
    cisa_kev_count: int = 0
    pci_in_scope_count: int = 0
    highest_priority: Optional[str] = None
    cves: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)


class CombinedRiskAssessment(BaseModel):
    corroborated_exposure: bool = False
    risk_tier: RiskTier = "INFO"
    rationale: str = "Sem sinais de ameaça ou vulnerabilidade registrados para o ativo."


class ConsolidatedAssetContext(BaseModel):
    asset_id: str
    host: Optional[str] = None
    owner: Optional[str] = None
    threat_intel: ThreatIntelAssetSummary = Field(default_factory=ThreatIntelAssetSummary)
    vulnerability_triage: VulnerabilityAssetSummary = Field(default_factory=VulnerabilityAssetSummary)
    combined_risk: CombinedRiskAssessment = Field(default_factory=CombinedRiskAssessment)


class CorrelationReport(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    total_assets: int = 0
    corroborated_assets: int = 0
    critical_assets: int = 0
    assets: list[ConsolidatedAssetContext] = Field(default_factory=list)


def _normalize_asset_id(
    candidate: Optional[str],
    host: Optional[str],
    inventory: Optional[AssetInventory],
) -> str:
    if candidate:
        cleaned = candidate.strip().lower()
        if ASSET_ID_RE.match(cleaned):
            return cleaned
    if host:
        return resolve_asset_id(host=host, inventory=inventory)
    return UNKNOWN_ASSET_ID


def _load_json_records(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {p}")
    raw = p.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    if p.suffix.lower() == ".jsonl":
        return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]
    parsed = json.loads(raw)
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    raise ValueError(f"Formato JSON inválido em {p}")


def _extract_ti_items(doc: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("results", "enriched_alerts", "alerts", "items", "entries"):
        val = doc.get(key)
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
    return [doc]


def _extract_indicator_and_verdict(item: dict[str, Any]) -> tuple[Optional[str], str]:
    verdict = str(item.get("verdict") or item.get("risk_verdict") or "unknown").strip().lower()
    if verdict not in _VERDICT_RANK:
        verdict = "unknown"

    for key in ("indicator", "ioc", "value", "target_value", "ip"):
        val = item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip(), verdict

    ind_obj = item.get("indicator_obj") or item.get("ioc_obj")
    if isinstance(ind_obj, dict):
        for key in ("value", "indicator", "ip"):
            val = ind_obj.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip(), verdict

    return None, verdict


def _extract_entry_hashes(item: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("entry_hash", "evidence_entry_hash"):
        val = item.get(key)
        if isinstance(val, str):
            candidates.append(val)

    for key in ("evidence_entry_hashes", "entry_hashes"):
        val = item.get(key)
        if isinstance(val, list):
            candidates.extend(v for v in val if isinstance(v, str))

    valid: list[str] = []
    for raw in candidates:
        cleaned = raw.strip().lower()
        if _SHA256_RE.match(cleaned):
            valid.append(cleaned)
    return valid


def _defang_ioc(value: str) -> str:
    defanged = re.sub(r"(?i)^https://", "hxxps://", value.strip())
    defanged = re.sub(r"(?i)^http://", "hxxp://", defanged)
    return defanged.replace(".", "[.]")


def _compute_risk(
    ti: ThreatIntelAssetSummary,
    vt: VulnerabilityAssetSummary,
) -> CombinedRiskAssessment:
    has_ti_signal = (
        ti.alert_count > 0
        or len(ti.malicious_iocs) > 0
        or len(ti.suspicious_iocs) > 0
        or ti.highest_verdict in ("malicious", "suspicious")
    )
    has_vuln_signal = vt.finding_count > 0

    corroborated = has_vuln_signal and (
        len(ti.malicious_iocs) > 0
        or len(ti.suspicious_iocs) > 0
        or ti.highest_verdict in ("malicious", "suspicious")
    )

    if corroborated and (
        ti.highest_verdict == "malicious"
        or vt.p0_count > 0
        or vt.cisa_kev_count > 0
    ):
        return CombinedRiskAssessment(
            corroborated_exposure=True,
            risk_tier="CRITICAL",
            rationale=(
                "Exposição corroborada: indicador malicioso/suspeito em TI combinado com "
                "achados críticos/KEV ou P0 no ativo."
            ),
        )

    if corroborated or ti.highest_verdict == "malicious" or vt.p0_count > 0 or vt.p1_count > 0:
        return CombinedRiskAssessment(
            corroborated_exposure=corroborated,
            risk_tier="HIGH",
            rationale=(
                "Sinal elevado de risco: alerta/IOC em TI ou vulnerabilidades P0/P1 "
                "identificadas no ativo."
            ),
        )

    if has_ti_signal or vt.p2_count > 0 or has_vuln_signal:
        return CombinedRiskAssessment(
            corroborated_exposure=False,
            risk_tier="MEDIUM",
            rationale="Sinais moderados de telemetria/TI ou vulnerabilidades de menor prioridade.",
        )

    return CombinedRiskAssessment()


def correlate_ti_and_triage(
    ti_paths: list[str | Path],
    triage_paths: list[str | Path],
    asset_inventory: Optional[AssetInventory] = None,
    evidence_paths: Optional[list[str | Path]] = None,
) -> CorrelationReport:
    records_by_asset: dict[str, ConsolidatedAssetContext] = {}
    sets_by_asset: dict[str, dict[str, set[str]]] = {}

    def get_ctx(
        aid: str,
        host: Optional[str] = None,
        owner: Optional[str] = None,
    ) -> ConsolidatedAssetContext:
        if aid not in records_by_asset:
            records_by_asset[aid] = ConsolidatedAssetContext(
                asset_id=aid,
                host=host,
                owner=owner,
            )
            sets_by_asset[aid] = {
                "mal_iocs": set(),
                "sus_iocs": set(),
                "rules": set(),
                "mitre": set(),
                "evidence_hashes": set(),
                "cves": set(),
                "fids": set(),
            }
        ctx = records_by_asset[aid]
        if host and not ctx.host:
            ctx.host = host
        if owner and not ctx.owner:
            ctx.owner = owner
        return ctx

    combined_ti_sources = [*ti_paths, *(evidence_paths or [])]

    for tpath in combined_ti_sources:
        for doc in _load_json_records(tpath):
            top_candidate = (
                doc.get("asset_id") or (doc.get("asset") or {}).get("asset_id")
                if isinstance(doc.get("asset"), dict)
                else doc.get("asset_id")
            )
            top_aid = _normalize_asset_id(
                top_candidate,
                doc.get("host"),
                asset_inventory,
            )
            doc_hashes = _extract_entry_hashes(doc)

            for item in _extract_ti_items(doc):
                aid = _normalize_asset_id(
                    item.get("asset_id") or top_aid,
                    item.get("host") or doc.get("host"),
                    asset_inventory,
                )
                ctx = get_ctx(aid, host=item.get("host") or doc.get("host"))
                ti = ctx.threat_intel
                s = sets_by_asset[aid]

                if item.get("rule_id"):
                    ti.alert_count += 1
                    s["rules"].add(str(item["rule_id"]).strip())
                if item.get("mitre_technique"):
                    tech = str(item["mitre_technique"]).strip().upper()
                    if re.match(r"^T\d{4}(\.\d{3})?$", tech):
                        s["mitre"].add(tech)

                for h in (*doc_hashes, *_extract_entry_hashes(item)):
                    s["evidence_hashes"].add(h)

                indicator, verdict = _extract_indicator_and_verdict(item)
                if indicator:
                    if verdict == "malicious":
                        s["mal_iocs"].add(indicator)
                    elif verdict == "suspicious":
                        s["sus_iocs"].add(indicator)

                if _VERDICT_RANK[verdict] > _VERDICT_RANK.get(ti.highest_verdict, 0):
                    ti.highest_verdict = verdict

    for vpath in triage_paths:
        for doc in _load_json_records(vpath):
            asset_obj = doc.get("asset") if isinstance(doc.get("asset"), dict) else {}
            doc_aid = _normalize_asset_id(
                asset_obj.get("asset_id") or doc.get("asset_id"),
                doc.get("host"),
                asset_inventory,
            )
            doc_owner = asset_obj.get("owner")
            findings = doc.get("findings") if isinstance(doc.get("findings"), list) else []

            if findings:
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    aid = _normalize_asset_id(
                        f.get("asset_id") or doc_aid,
                        f.get("host") or doc.get("host"),
                        asset_inventory,
                    )
                    ctx = get_ctx(aid, owner=f.get("owner") or doc_owner)
                    vt = ctx.vulnerability_triage
                    s = sets_by_asset[aid]

                    vt.finding_count += 1
                    prio = str(f.get("priority") or "").strip().upper()
                    if prio == "P0":
                        vt.p0_count += 1
                    elif prio == "P1":
                        vt.p1_count += 1
                    elif prio == "P2":
                        vt.p2_count += 1
                    elif prio == "P3":
                        vt.p3_count += 1

                    if prio in _PRIORITY_RANK:
                        if vt.highest_priority is None or _PRIORITY_RANK[prio] > _PRIORITY_RANK.get(vt.highest_priority, 0):
                            vt.highest_priority = prio

                    if bool(f.get("in_cisa_kev")):
                        vt.cisa_kev_count += 1
                    if bool(f.get("pci_dss_in_scope")):
                        vt.pci_in_scope_count += 1

                    if f.get("cve_id"):
                        s["cves"].add(str(f["cve_id"]).strip().upper())
                    if f.get("finding_id"):
                        s["fids"].add(str(f["finding_id"]).strip())
            else:
                ctx = get_ctx(doc_aid, owner=doc_owner)
                summary = doc.get("summary") if isinstance(doc.get("summary"), dict) else {}
                vt = ctx.vulnerability_triage
                vt.finding_count += int(summary.get("total", 0) or 0)
                vt.p0_count += int(summary.get("P0", 0) or 0)
                vt.p1_count += int(summary.get("P1", 0) or 0)
                vt.p2_count += int(summary.get("P2", 0) or 0)
                vt.p3_count += int(summary.get("P3", 0) or 0)
                vt.pci_in_scope_count += int(summary.get("pci_in_scope_count", 0) or 0)

    ordered: list[ConsolidatedAssetContext] = []
    for aid in sorted(records_by_asset.keys()):
        ctx = records_by_asset[aid]
        s = sets_by_asset[aid]
        ti = ctx.threat_intel
        vt = ctx.vulnerability_triage

        ti.malicious_iocs = sorted(s["mal_iocs"])
        ti.suspicious_iocs = sorted(s["sus_iocs"])
        ti.ioc_count = len(ti.malicious_iocs) + len(ti.suspicious_iocs)
        ti.matched_rules = sorted(s["rules"])
        ti.mitre_techniques = sorted(s["mitre"])
        ti.evidence_entry_hashes = sorted(s["evidence_hashes"])

        vt.cves = sorted(s["cves"])
        vt.finding_ids = sorted(s["fids"])

        ctx.combined_risk = _compute_risk(ti, vt)
        ordered.append(ctx)

    ordered.sort(
        key=lambda c: (-_RISK_RANK[c.combined_risk.risk_tier], c.asset_id)
    )

    return CorrelationReport(
        total_assets=len(ordered),
        corroborated_assets=sum(1 for c in ordered if c.combined_risk.corroborated_exposure),
        critical_assets=sum(1 for c in ordered if c.combined_risk.risk_tier == "CRITICAL"),
        assets=ordered,
    )


def render_correlation_markdown(report: CorrelationReport) -> str:
    lines: list[str] = [
        "# vtx-detection-lab — Resumo Executivo SOC (Correlação por Ativo)",
        "",
        "## Resumo Geral",
        "",
        "| Métrica | Quantidade |",
        "| :--- | ---: |",
        f"| Ativos consolidados | {report.total_assets} |",
        f"| Ativos com exposição corroborada (TI + Vuln) | {report.corroborated_assets} |",
        f"| Ativos em risco CRITICAL | {report.critical_assets} |",
        "",
        "## Ativos com Exposição Corroborada (Ação Prioritária SOC)",
        "",
    ]

    corroborated = [a for a in report.assets if a.combined_risk.corroborated_exposure]
    if not corroborated:
        lines.append(
            "_Nenhum ativo com exposição corroborada (TI + Vulnerabilidades) nesta execução._"
        )
        lines.append("")
    else:
        for asset in corroborated:
            ti = asset.threat_intel
            vt = asset.vulnerability_triage
            risk = asset.combined_risk

            defanged_mal = ", ".join(f"`{_defang_ioc(i)}`" for i in ti.malicious_iocs) or "Nenhum"
            defanged_sus = ", ".join(f"`{_defang_ioc(i)}`" for i in ti.suspicious_iocs) or "Nenhum"
            rules_str = ", ".join(f"`{r}`" for r in ti.matched_rules) or "Nenhuma"
            mitre_str = ", ".join(f"`{m}`" for m in ti.mitre_techniques) or "Nenhuma"
            hashes_str = ", ".join(f"`{h}`" for h in ti.evidence_entry_hashes) or "Nenhum"
            cves_str = ", ".join(f"`{c}`" for c in vt.cves) or "Nenhum"

            lines.extend(
                [
                    f"### `{asset.asset_id}` — Risco `{risk.risk_tier}`",
                    "",
                    f"- **Host / Responsável:** `{asset.host or 'N/A'}` / `{asset.owner or 'N/A'}`",
                    f"- **Threat Intel:** veredito `{ti.highest_verdict}` | alertas: `{ti.alert_count}` | IOCs maliciosos: {defanged_mal} | IOCs suspeitos: {defanged_sus}",
                    f"- **Detecção / MITRE:** regras {rules_str} | técnicas {mitre_str}",
                    f"- **Evidência SHA-256 (`entry_hash`):** {hashes_str}",
                    f"- **Vulnerabilidades:** total `{vt.finding_count}` | maior prioridade `{vt.highest_priority or 'N/A'}` (P0: {vt.p0_count}, P1: {vt.p1_count}, P2: {vt.p2_count}, P3: {vt.p3_count}) | CISA KEV: `{vt.cisa_kev_count}` | PCI-DSS: `{vt.pci_in_scope_count}`",
                    f"- **CVEs associados:** {cves_str}",
                    f"- **Justificativa:** {risk.rationale}",
                    "",
                ]
            )

    lines.extend(
        [
            "## Panorama Geral por Ativo",
            "",
        ]
    )
    if not report.assets:
        lines.append("_Nenhum ativo registrado no relatório._")
        lines.append("")
    else:
        lines.extend(
            [
                "| Asset ID | Risk Tier | Corroborado | Veredito TI | IOCs TI | Achados Vuln | Maior Prioridade | CISA KEV | Evidência SHA-256 |",
                "| :--- | :---: | :---: | :---: | ---: | ---: | :---: | ---: | :--- |",
            ]
        )
        for asset in report.assets:
            ti = asset.threat_intel
            vt = asset.vulnerability_triage
            corr_flag = "SIM" if asset.combined_risk.corroborated_exposure else "NAO"
            if ti.evidence_entry_hashes:
                short_hashes = ", ".join(f"`{h[:12]}`" for h in ti.evidence_entry_hashes[:2])
                if len(ti.evidence_entry_hashes) > 2:
                    short_hashes += f" (+{len(ti.evidence_entry_hashes) - 2})"
            else:
                short_hashes = "-"
            lines.append(
                f"| `{asset.asset_id}` | `{asset.combined_risk.risk_tier}` | {corr_flag} | "
                f"`{ti.highest_verdict}` | {ti.ioc_count} | {vt.finding_count} | "
                f"`{vt.highest_priority or '-'}` | {vt.cisa_kev_count} | {short_hashes} |"
            )
        lines.append("")

    return "\n".join(lines)


def save_correlation_report(report: CorrelationReport, output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return out


def save_correlation_markdown(report: CorrelationReport, output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_correlation_markdown(report), encoding="utf-8")
    return out
