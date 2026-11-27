#!/usr/bin/env bash
set -euo pipefail

# Conecta alertas JSONL do vtx-detection-lab ao vtx-ti-enricher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ALERTS_FILE="${ALERTS_FILE:-${REPO_ROOT}/data/alerts.jsonl}"
OUTPUT_FILE="${OUTPUT_FILE:-${REPO_ROOT}/data/enriched_alerts.jsonl}"
ENRICHER_DIR="${ENRICHER_DIR:-${REPO_ROOT}/../vtx-ti-enricher}"
ENRICHER_SUBCMD="${ENRICHER_SUBCMD:-}"
DRY_RUN=false

usage() {
  cat << 'USAGE'
Uso: ./scripts/enrich_alerts.sh [opções]

Opções:
  -i, --input FILE          Arquivo JSONL de alertas (padrão: data/alerts.jsonl)
  -o, --output FILE         Arquivo JSONL enriquecido (padrão: data/enriched_alerts.jsonl)
  -e, --enricher-dir DIR    Caminho do repo vtx-ti-enricher (padrão: ../vtx-ti-enricher)
      --dry-run             Apenas extrai e lista os IOCs sem chamar o vtx-ti-enricher
  -h, --help                Exibe esta ajuda
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--input) ALERTS_FILE="$2"; shift 2 ;;
    -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
    -e|--enricher-dir) ENRICHER_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opção desconhecida: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -f "${ALERTS_FILE}" ]]; then
  echo "Erro: arquivo de alertas não encontrado: ${ALERTS_FILE}" >&2
  exit 1
fi

TMP_IOCS="$(mktemp)"
trap 'rm -f "${TMP_IOCS}"' EXIT

# Extrai IOCs únicos (IP, domínio, URL, hash) dos alertas JSONL
python3 - "${ALERTS_FILE}" "${TMP_IOCS}" << 'PY'
import json
import sys
from pathlib import Path

alerts_path = Path(sys.argv[1])
iocs_path = Path(sys.argv[2])

IOC_KEYS = {
    "ioc", "indicator", "src_ip", "dst_ip", "dest_ip", "source_ip", "ip",
    "domain", "hostname", "query", "url", "uri", "sha256", "sha1", "md5", "hash",
}

def collect_iocs(obj, found):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in IOC_KEYS and isinstance(v, str) and v.strip():
                found.add(v.strip())
            elif isinstance(v, (dict, list)):
                collect_iocs(v, found)
    elif isinstance(obj, list):
        for item in obj:
            collect_iocs(item, found)

found = set()
line_count = 0
for raw_line in alerts_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line:
        continue
    line_count += 1
    collect_iocs(json.loads(line), found)

sorted_iocs = sorted(found)
iocs_path.write_text("\n".join(sorted_iocs) + ("\n" if sorted_iocs else ""), encoding="utf-8")
print(f"[vtx-detection-lab] {line_count} alerta(s) lido(s), {len(sorted_iocs)} IOC(s) único(s) extraído(s).")
PY

if [[ ! -s "${TMP_IOCS}" ]]; then
  echo "[vtx-detection-lab] Nenhum IOC encontrado em ${ALERTS_FILE}. Nada a enriquecer."
  exit 0
fi

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[dry-run] IOCs extraídos:"
  cat "${TMP_IOCS}"
  exit 0
fi

# Resolve o executável do vtx-ti-enricher
if command -v vtx-ti-enricher >/dev/null 2>&1; then
  ENRICHER_BIN=("vtx-ti-enricher")
elif [[ -x "${ENRICHER_DIR}/.venv/bin/vtx-ti-enricher" ]]; then
  ENRICHER_BIN=("${ENRICHER_DIR}/.venv/bin/vtx-ti-enricher")
elif [[ -x "${ENRICHER_DIR}/.venv/bin/python" ]]; then
  ENRICHER_BIN=("${ENRICHER_DIR}/.venv/bin/python" "-m" "vtx_ti_enricher")
else
  echo "Erro: vtx-ti-enricher não encontrado no PATH nem em ${ENRICHER_DIR}/.venv." >&2
  exit 1
fi

mkdir -p "$(dirname "${OUTPUT_FILE}")"

# Ajustar subcomando/flags abaixo caso a CLI do vtx-ti-enricher use argumentos distintos
CMD=("${ENRICHER_BIN[@]}")
if [[ -n "${ENRICHER_SUBCMD}" ]]; then
  CMD+=("${ENRICHER_SUBCMD}")
fi
CMD+=("--input" "${TMP_IOCS}" "--output" "${OUTPUT_FILE}")

echo "[vtx-detection-lab] Executando: ${CMD[*]}"
"${CMD[@]}"
echo "[vtx-detection-lab] Alertas enriquecidos salvos em: ${OUTPUT_FILE}"
