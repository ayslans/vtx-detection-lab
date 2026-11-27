#!/usr/bin/env bash
set -euo pipefail

# Conecta alertas JSON/JSONL do vtx-detection-lab ao vtx-ti-enricher (local ou Docker GHCR)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ALERTS_FILE="${ALERTS_FILE:-${REPO_ROOT}/data/alerts.jsonl}"
OUTPUT_FILE="${OUTPUT_FILE:-${REPO_ROOT}/data/enriched/enrich_report.json}"
ENRICHER_DIR="${ENRICHER_DIR:-${REPO_ROOT}/../vtx-ti-enricher}"
ENRICHER_DOCKER_IMAGE="${ENRICHER_DOCKER_IMAGE:-ghcr.io/ayslans/vtx-ti-enricher:0.2.0}"
PROVIDERS="${PROVIDERS:-abuseipdb,otx,urlhaus,virustotal}"
CACHE_DB=""
MD_OUT=""
STIX_OUT=""
STIX_MIN_VERDICT=""
EVIDENCE_LOG=""
ASSET_ID=""
VERIFY_EVIDENCE=false
NO_CACHE=false
INCLUDE_INTERNAL=false
NO_DEFANG=false
DRY_RUN=false
USE_DOCKER=false
TMP_DIR=""

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

ensure_tmp_dir() {
  if [[ -z "${TMP_DIR}" ]]; then
    TMP_DIR="$(mktemp -d)"
    chmod 755 "${TMP_DIR}"
  fi
}

usage() {
  cat << 'USAGE'
Uso: ./scripts/enrich_alerts.sh [opções]

Opções:
  -i, --input FILE             Alertas (.jsonl, .json, .txt, .csv) [padrão: data/alerts.jsonl]
  -o, --output FILE            Saída JSON (EnrichBatchReport ou ParseReport em --dry-run)
                               [padrão: data/enriched/enrich_report.json]
      --md-out FILE            Exporta relatório executivo SOC em Markdown
      --stix-out FILE          Exporta bundle STIX 2.1 em JSON
      --stix-min-verdict LVL   Veredito mínimo no STIX (unknown|benign|suspicious|malicious)
      --evidence-log FILE      Grava/anexa ledger append-only SHA-256 (JSONL)
      --asset-id ID            Asset ID canônico gravado no ledger de evidências
      --verify-evidence        Executa 'vtx-ti-enricher verify-evidence' após gravar o ledger
  -p, --providers LIST         Provedores separados por vírgula
                               [padrão: abuseipdb,otx,urlhaus,virustotal]
      --cache-db FILE          Banco SQLite WAL [padrão: <enricher-dir>/.vtx_ti_cache.sqlite3]
      --no-cache               Desativa cache SQLite nesta execução
      --include-internal       Inclui IPs/indicadores internos (desativa guarda OPSEC)
      --no-defang              Exibe indicadores sem defang no terminal/Markdown
  -e, --enricher-dir DIR       Caminho do repo vtx-ti-enricher [padrão: ../vtx-ti-enricher]
      --docker                 Força execução via container Docker (ENRICHER_DOCKER_IMAGE)
      --dry-run                Executa 'parse' offline (e gera ledger via 'export' se --evidence-log for informado)
  -h, --help                   Exibe esta ajuda
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--input) ALERTS_FILE="$2"; shift 2 ;;
    -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
    --md-out) MD_OUT="$2"; shift 2 ;;
    --stix-out) STIX_OUT="$2"; shift 2 ;;
    --stix-min-verdict) STIX_MIN_VERDICT="$2"; shift 2 ;;
    --evidence-log) EVIDENCE_LOG="$2"; shift 2 ;;
    --asset-id) ASSET_ID="$2"; shift 2 ;;
    --verify-evidence) VERIFY_EVIDENCE=true; shift ;;
    -p|--providers) PROVIDERS="$2"; shift 2 ;;
    --cache-db) CACHE_DB="$2"; shift 2 ;;
    --no-cache) NO_CACHE=true; shift ;;
    --include-internal) INCLUDE_INTERNAL=true; shift ;;
    --no-defang) NO_DEFANG=true; shift ;;
    -e|--enricher-dir) ENRICHER_DIR="$2"; shift 2 ;;
    --docker) USE_DOCKER=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Erro: opção desconhecida: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -f "${ALERTS_FILE}" ]]; then
  echo "Erro: arquivo de alertas não encontrado: ${ALERTS_FILE}" >&2
  exit 1
fi

if [[ -z "${CACHE_DB}" ]]; then
  CACHE_DB="${ENRICHER_DIR}/.vtx_ti_cache.sqlite3"
fi

# Resolve o executável local ou faz fallback para Docker GHCR
ENRICHER_BIN=()
if [[ "${USE_DOCKER}" != "true" ]]; then
  if command -v vtx-ti-enricher >/dev/null 2>&1; then
    ENRICHER_BIN=("vtx-ti-enricher")
  elif [[ -x "${ENRICHER_DIR}/.venv/bin/vtx-ti-enricher" ]]; then
    ENRICHER_BIN=("${ENRICHER_DIR}/.venv/bin/vtx-ti-enricher")
  elif [[ -x "${ENRICHER_DIR}/.venv/bin/python" ]]; then
    ENRICHER_BIN=("${ENRICHER_DIR}/.venv/bin/python" "-m" "vtx_ti_enricher.main")
  fi
fi

if [[ ${#ENRICHER_BIN[@]} -eq 0 ]]; then
  if command -v docker >/dev/null 2>&1; then
    USE_DOCKER=true
  else
    echo "Erro: vtx-ti-enricher não encontrado localmente e docker indisponível." >&2
    exit 1
  fi
fi

# Normaliza JSONL (1 alerta por linha) para .json legível inclusive por container non-root
TARGET_INPUT="${ALERTS_FILE}"
if [[ "${ALERTS_FILE}" == *.jsonl ]]; then
  ensure_tmp_dir
  TARGET_INPUT="${TMP_DIR}/alerts.json"
  python3 - "${ALERTS_FILE}" "${TARGET_INPUT}" << 'INNER_PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

records = []
for idx, raw in enumerate(src.read_text(encoding="utf-8").splitlines(), start=1):
    line = raw.strip()
    if not line:
        continue
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Erro JSON na linha {idx} de {src}: {exc}") from exc

if not records:
    raise SystemExit(f"Aviso: nenhum alerta encontrado em {src}.")

dst.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"[vtx-detection-lab] {len(records)} alerta(s) JSONL preparados para o vtx-ti-enricher.")
INNER_PY
  chmod 644 "${TARGET_INPUT}"
fi

OUT_DIR="$(dirname "${OUTPUT_FILE}")"
mkdir -p "${OUT_DIR}"
[[ -n "${MD_OUT}" ]] && mkdir -p "$(dirname "${MD_OUT}")"
[[ -n "${STIX_OUT}" ]] && mkdir -p "$(dirname "${STIX_OUT}")"
[[ -n "${EVIDENCE_LOG}" ]] && mkdir -p "$(dirname "${EVIDENCE_LOG}")"

if [[ "${USE_DOCKER}" == "true" ]]; then
  ABS_IN_DIR="$(cd "$(dirname "${TARGET_INPUT}")" && pwd)"
  IN_BASE="$(basename "${TARGET_INPUT}")"
  ABS_OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
  OUT_BASE="$(basename "${OUTPUT_FILE}")"
  chmod 777 "${ABS_OUT_DIR}"

  DOCKER_ARGS=(
    docker run --rm
    -v "${ABS_IN_DIR}:/data/in:ro"
    -v "${ABS_OUT_DIR}:/data/out"
    "${ENRICHER_DOCKER_IMAGE}"
  )

  if [[ "${DRY_RUN}" == "true" ]]; then
    CMD=("${DOCKER_ARGS[@]}" "parse" "/data/in/${IN_BASE}" "--output" "/data/out/${OUT_BASE}")
    [[ "${INCLUDE_INTERNAL}" == "true" ]] && CMD+=("--include-internal")
    [[ "${NO_DEFANG}" == "true" ]] && CMD+=("--no-defang")
  else
    CMD=(
      "${DOCKER_ARGS[@]}" "enrich" "/data/in/${IN_BASE}"
      "--providers" "${PROVIDERS}"
      "--cache-db" "/data/out/cache.sqlite3"
      "--output" "/data/out/${OUT_BASE}"
    )
    [[ "${NO_CACHE}" == "true" ]] && CMD+=("--no-cache")
    [[ "${INCLUDE_INTERNAL}" == "true" ]] && CMD+=("--include-internal")
    [[ "${NO_DEFANG}" == "true" ]] && CMD+=("--no-defang")
    [[ -n "${MD_OUT}" ]] && CMD+=("--md-out" "/data/out/$(basename "${MD_OUT}")")
    [[ -n "${STIX_OUT}" ]] && CMD+=("--stix-out" "/data/out/$(basename "${STIX_OUT}")")
    [[ -n "${STIX_MIN_VERDICT}" ]] && CMD+=("--stix-min-verdict" "${STIX_MIN_VERDICT}")
    [[ -n "${EVIDENCE_LOG}" ]] && CMD+=("--evidence-log" "/data/out/$(basename "${EVIDENCE_LOG}")")
    [[ -n "${ASSET_ID}" ]] && CMD+=("--asset-id" "${ASSET_ID}")
  fi
else
  if [[ "${DRY_RUN}" == "true" ]]; then
    CMD=("${ENRICHER_BIN[@]}" "parse" "${TARGET_INPUT}" "--output" "${OUTPUT_FILE}")
    [[ "${INCLUDE_INTERNAL}" == "true" ]] && CMD+=("--include-internal")
    [[ "${NO_DEFANG}" == "true" ]] && CMD+=("--no-defang")
  else
    CMD=(
      "${ENRICHER_BIN[@]}" "enrich" "${TARGET_INPUT}"
      "--providers" "${PROVIDERS}"
      "--cache-db" "${CACHE_DB}"
      "--output" "${OUTPUT_FILE}"
    )
    [[ "${NO_CACHE}" == "true" ]] && CMD+=("--no-cache")
    [[ "${INCLUDE_INTERNAL}" == "true" ]] && CMD+=("--include-internal")
    [[ "${NO_DEFANG}" == "true" ]] && CMD+=("--no-defang")
    [[ -n "${MD_OUT}" ]] && CMD+=("--md-out" "${MD_OUT}")
    [[ -n "${STIX_OUT}" ]] && CMD+=("--stix-out" "${STIX_OUT}")
    [[ -n "${STIX_MIN_VERDICT}" ]] && CMD+=("--stix-min-verdict" "${STIX_MIN_VERDICT}")
    [[ -n "${EVIDENCE_LOG}" ]] && CMD+=("--evidence-log" "${EVIDENCE_LOG}")
    [[ -n "${ASSET_ID}" ]] && CMD+=("--asset-id" "${ASSET_ID}")
  fi
fi

echo "[vtx-detection-lab] Executando: ${CMD[*]}"
"${CMD[@]}"

# Em --dry-run com --evidence-log, converte o ParseReport para EnrichBatchReport v3.0 offline e grava o ledger via export
if [[ "${DRY_RUN}" == "true" && -n "${EVIDENCE_LOG}" ]]; then
  ensure_tmp_dir
  DRY_BATCH="${TMP_DIR}/dry_run_batch.json"
  INDICATOR_COUNT="$(python3 - "${OUTPUT_FILE}" "${DRY_BATCH}" << 'BATCH_PY'
import json
import sys
from pathlib import Path

parse_path = Path(sys.argv[1])
batch_path = Path(sys.argv[2])
parsed = json.loads(parse_path.read_text(encoding="utf-8"))
indicators = parsed.get("indicators", [])

batch = {
    "schema_version": "3.0",
    "input_source": parsed.get("input_source", str(parse_path)),
    "providers_enabled": [],
    "total_enriched": len(indicators),
    "skipped_internal": int(parsed.get("summary", {}).get("skipped_internal", 0)),
    "items": [
        {
            "ioc": ind,
            "provider_results": [],
            "assessment": {
                "verdict": "unknown",
                "composite_score": 0.0,
                "confidence": "none",
                "responding_providers": 0,
                "malicious_providers": 0,
                "corroborated": False,
                "recommended_action": "Dry-run parse only; live TI lookup pending.",
            },
        }
        for ind in indicators
    ],
}
batch_path.write_text(json.dumps(batch, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(len(indicators))
BATCH_PY
)"
  chmod 644 "${DRY_BATCH}"

  if [[ "${INDICATOR_COUNT}" -gt 0 ]]; then
    if [[ "${USE_DOCKER}" == "true" ]]; then
      ABS_EVID_DIR="$(cd "$(dirname "${EVIDENCE_LOG}")" && pwd)"
      EVID_BASE="$(basename "${EVIDENCE_LOG}")"
      chmod 777 "${ABS_EVID_DIR}"
      EXPORT_CMD=(
        docker run --rm
        -v "${TMP_DIR}:/data/tmp:ro"
        -v "${ABS_EVID_DIR}:/data/evidence"
        "${ENRICHER_DOCKER_IMAGE}"
        "export" "/data/tmp/dry_run_batch.json"
        "--evidence-log" "/data/evidence/${EVID_BASE}"
      )
      [[ -n "${ASSET_ID}" ]] && EXPORT_CMD+=("--asset-id" "${ASSET_ID}")
    else
      EXPORT_CMD=(
        "${ENRICHER_BIN[@]}" "export" "${DRY_BATCH}"
        "--evidence-log" "${EVIDENCE_LOG}"
      )
      [[ -n "${ASSET_ID}" ]] && EXPORT_CMD+=("--asset-id" "${ASSET_ID}")
    fi
    echo "[vtx-detection-lab] Gravando ledger SHA-256 (dry-run): ${EXPORT_CMD[*]}"
    "${EXPORT_CMD[@]}"
  else
    echo "[vtx-detection-lab] Nenhum indicador enriquecível no dry-run; ledger não alterado."
  fi
fi

# Gate de integridade criptográfica SHA-256
if [[ "${VERIFY_EVIDENCE}" == "true" && -n "${EVIDENCE_LOG}" && -s "${EVIDENCE_LOG}" ]]; then
  if [[ "${USE_DOCKER}" == "true" ]]; then
    ABS_EVID_DIR="$(cd "$(dirname "${EVIDENCE_LOG}")" && pwd)"
    EVID_BASE="$(basename "${EVIDENCE_LOG}")"
    VERIFY_CMD=(
      docker run --rm
      -v "${ABS_EVID_DIR}:/data/evidence:ro"
      "${ENRICHER_DOCKER_IMAGE}"
      "verify-evidence" "/data/evidence/${EVID_BASE}"
    )
  else
    VERIFY_CMD=("${ENRICHER_BIN[@]}" "verify-evidence" "${EVIDENCE_LOG}")
  fi
  echo "[vtx-detection-lab] Verificando integridade SHA-256: ${VERIFY_CMD[*]}"
  "${VERIFY_CMD[@]}"
fi
