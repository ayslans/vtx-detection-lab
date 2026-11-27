#!/usr/bin/env bash
set -euo pipefail

# Conecta alertas JSON/JSONL do vtx-detection-lab ao vtx-ti-enricher (local ou Docker GHCR)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ALERTS_FILE="${ALERTS_FILE:-${REPO_ROOT}/data/alerts.jsonl}"
OUTPUT_FILE="${OUTPUT_FILE:-${REPO_ROOT}/data/enriched/enrich_report.json}"
ENRICHER_DIR="${ENRICHER_DIR:-${REPO_ROOT}/../vtx-ti-enricher}"
ENRICHER_DOCKER_IMAGE="${ENRICHER_DOCKER_IMAGE:-ghcr.io/ayslans/vtx-ti-enricher:0.1.1}"
PROVIDERS="${PROVIDERS:-abuseipdb,otx,urlhaus,virustotal}"
CACHE_DB=""
MD_OUT=""
STIX_OUT=""
STIX_MIN_VERDICT=""
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
      --docker                 Força execução via container Docker (ENRICHER_DOCKER_IMAGE)
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
  TMP_DIR="$(mktemp -d)"
  chmod 755 "${TMP_DIR}"
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
  fi
fi

echo "[vtx-detection-lab] Executando: ${CMD[*]}"
"${CMD[@]}"
