#!/usr/bin/env bash
set -euo pipefail

# Conecta alertas JSON/JSONL do vtx-detection-lab ao vtx-ti-enricher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ALERTS_FILE="${ALERTS_FILE:-${REPO_ROOT}/data/alerts.jsonl}"
OUTPUT_FILE="${OUTPUT_FILE:-${REPO_ROOT}/data/enriched/enrich_report.json}"
ENRICHER_DIR="${ENRICHER_DIR:-${REPO_ROOT}/../vtx-ti-enricher}"
PROVIDERS="${PROVIDERS:-abuseipdb,otx,urlhaus,virustotal}"
CACHE_DB=""
MD_OUT=""
STIX_OUT=""
STIX_MIN_VERDICT=""
NO_CACHE=false
INCLUDE_INTERNAL=false
NO_DEFANG=false
DRY_RUN=false
TMP_JSON=""

cleanup() {
  if [[ -n "${TMP_JSON}" && -f "${TMP_JSON}" ]]; then
    rm -f "${TMP_JSON}"
  fi
}
trap cleanup EXIT

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
  -p, --providers LIST         Provedores separados por vírgula
                               [padrão: abuseipdb,otx,urlhaus,virustotal]
      --cache-db FILE          Banco SQLite WAL [padrão: <enricher-dir>/.vtx_ti_cache.sqlite3]
      --no-cache               Desativa cache SQLite nesta execução
      --include-internal       Inclui IPs/indicadores internos (desativa guarda OPSEC)
      --no-defang              Exibe indicadores sem defang no terminal/Markdown
  -e, --enricher-dir DIR       Caminho do repo vtx-ti-enricher [padrão: ../vtx-ti-enricher]
      --dry-run                Executa apenas 'vtx-ti-enricher parse' (sem APIs externas)
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
    -p|--providers) PROVIDERS="$2"; shift 2 ;;
    --cache-db) CACHE_DB="$2"; shift 2 ;;
    --no-cache) NO_CACHE=true; shift ;;
    --include-internal) INCLUDE_INTERNAL=true; shift ;;
    --no-defang) NO_DEFANG=true; shift ;;
    -e|--enricher-dir) ENRICHER_DIR="$2"; shift 2 ;;
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

# Resolve o executável do vtx-ti-enricher
if command -v vtx-ti-enricher >/dev/null 2>&1; then
  ENRICHER_BIN=("vtx-ti-enricher")
elif [[ -x "${ENRICHER_DIR}/.venv/bin/vtx-ti-enricher" ]]; then
  ENRICHER_BIN=("${ENRICHER_DIR}/.venv/bin/vtx-ti-enricher")
elif [[ -x "${ENRICHER_DIR}/.venv/bin/python" ]]; then
  ENRICHER_BIN=("${ENRICHER_DIR}/.venv/bin/python" "-m" "vtx_ti_enricher.main")
else
  echo "Erro: vtx-ti-enricher não encontrado no PATH nem em ${ENRICHER_DIR}/.venv." >&2
  exit 1
fi

# Normaliza JSONL (1 objeto JSON por linha) para um arquivo .json temporário
TARGET_INPUT="${ALERTS_FILE}"
if [[ "${ALERTS_FILE}" == *.jsonl ]]; then
  TMP_JSON="$(mktemp /tmp/vtx_alerts_XXXXXX.json)"
  python3 - "${ALERTS_FILE}" "${TMP_JSON}" << 'PY'
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
PY
  TARGET_INPUT="${TMP_JSON}"
fi

mkdir -p "$(dirname "${OUTPUT_FILE}")"
[[ -n "${MD_OUT}" ]] && mkdir -p "$(dirname "${MD_OUT}")"
[[ -n "${STIX_OUT}" ]] && mkdir -p "$(dirname "${STIX_OUT}")"

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
fi

echo "[vtx-detection-lab] Executando: ${CMD[*]}"
"${CMD[@]}"
