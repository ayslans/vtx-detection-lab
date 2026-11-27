import json
from pathlib import Path

from typer.testing import CliRunner

from vtx_detection_lab.assets import UNKNOWN_ASSET_ID, load_asset_inventory
from vtx_detection_lab.correlator import CorrelationReport, correlate_ti_and_triage
from vtx_detection_lab.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_ASSETS = REPO_ROOT / "examples" / "assets.yaml"
runner = CliRunner()


def test_correlate_merges_ti_and_triage_by_asset_id(tmp_path: Path) -> None:
    ti_payload = {
        "schema_version": "1.0",
        "source": "vtx-ti-enricher",
        "results": [
            {
                "asset_id": "pay-lnx-gw-01",
                "host": "PAY-LNX-GW-01",
                "rule_id": "VTX-1005",
                "mitre_technique": "T1190",
                "indicator": "203.0.113.42",
                "verdict": "malicious",
            }
        ],
    }
    triage_payload = {
        "schema_version": "1.0",
        "source": "vtx-vuln-triage-ai",
        "asset": {
            "asset_id": "pay-lnx-gw-01",
            "name": "Gateway de Pagamentos Linux",
            "owner": "squad-pagamentos@empresa.local",
            "environment": "prod",
            "exposure": "internet",
            "criticality": "critical",
        },
        "summary": {
            "total": 1,
            "P0": 1,
            "P1": 0,
            "P2": 0,
            "P3": 0,
            "pci_in_scope_count": 1,
        },
        "findings": [
            {
                "finding_id": "vtx-vuln-abcdef1234567890",
                "cve_id": "CVE-2026-124851",
                "package_name": "libzstd1",
                "installed_version": "1.5.5",
                "fixed_version": "1.5.6",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "epss_score": 0.85,
                "in_cisa_kev": True,
                "target": "pay-lnx-gw-01:latest",
                "asset_id": "pay-lnx-gw-01",
                "owner": "squad-pagamentos@empresa.local",
                "asset_criticality": "CDE",
                "pci_dss_in_scope": True,
                "priority": "P0",
                "sla_days": 2,
                "triaged_at": "2026-11-27T04:00:00Z",
                "sla_due_at": "2026-11-29T04:00:00Z",
                "rationale": ["KEV ativo em CDE"],
            }
        ],
    }

    ti_file = tmp_path / "ti_report.json"
    triage_file = tmp_path / "triage_report.json"
    out_file = tmp_path / "correlated.json"
    ti_file.write_text(json.dumps(ti_payload), encoding="utf-8")
    triage_file.write_text(json.dumps(triage_payload), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "correlate",
            "--ti-input",
            str(ti_file),
            "--triage-input",
            str(triage_file),
            "--assets",
            str(EXAMPLES_ASSETS),
            "--output",
            str(out_file),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out_file.exists()

    report = CorrelationReport.model_validate_json(out_file.read_text(encoding="utf-8"))
    assert report.total_assets == 1
    assert report.corroborated_assets == 1
    assert report.critical_assets == 1

    ctx = report.assets[0]
    assert ctx.asset_id == "pay-lnx-gw-01"
    assert ctx.threat_intel.highest_verdict == "malicious"
    assert ctx.threat_intel.malicious_iocs == ["203.0.113.42"]
    assert ctx.threat_intel.matched_rules == ["VTX-1005"]
    assert ctx.threat_intel.mitre_techniques == ["T1190"]
    assert ctx.vulnerability_triage.finding_count == 1
    assert ctx.vulnerability_triage.p0_count == 1
    assert ctx.vulnerability_triage.cves == ["CVE-2026-124851"]
    assert ctx.combined_risk.corroborated_exposure is True
    assert ctx.combined_risk.risk_tier == "CRITICAL"


def test_correlate_falls_back_to_unknown_asset_when_missing() -> None:
    inv = load_asset_inventory(EXAMPLES_ASSETS)
    report = correlate_ti_and_triage(
        ti_paths=[],
        triage_paths=[],
        asset_inventory=inv,
    )
    assert report.total_assets == 0

    ti_unknown = [{"verdict": "suspicious", "indicator": "198.51.100.99"}]
    # Usa arquivo temporário via correlate_ti_and_triage passando lista em tmp_path
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
        json.dump(ti_unknown, tf)
        tpath = Path(tf.name)
    try:
        rep = correlate_ti_and_triage([tpath], [], asset_inventory=inv)
        assert rep.total_assets == 1
        assert rep.assets[0].asset_id == UNKNOWN_ASSET_ID
        assert rep.assets[0].threat_intel.highest_verdict == "suspicious"
    finally:
        tpath.unlink(missing_ok=True)
