#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat << 'USAGE'
Uso:
  ./scripts/inject_algorithm.sh <arquivo_alvo> <marcador_ancora> <arquivo_algoritmo> [--after | --before] [--id-marker <id>]
USAGE
  exit 1
}

if [[ $# -lt 3 ]]; then
  usage
fi

TARGET_FILE="$1"
ANCHOR="$2"
ALGO_FILE="$3"
POSITION="--before"
ID_MARKER=""

shift 3
while [[ $# -gt 0 ]]; do
  case "$1" in
    --after|--before)
      POSITION="$1"
      shift
      ;;
    --id-marker)
      ID_MARKER="${2:-}"
      shift 2
      ;;
    *)
      echo "Argumento desconhecido: $1" >&2
      usage
      ;;
  esac
done

[[ -f "${TARGET_FILE}" ]] || { echo "Erro: arquivo alvo não encontrado: ${TARGET_FILE}" >&2; exit 1; }
[[ -f "${ALGO_FILE}" ]] || { echo "Erro: arquivo do algoritmo não encontrado: ${ALGO_FILE}" >&2; exit 1; }

if [[ -z "${ID_MARKER}" ]]; then
  ID_MARKER="VTX_INJECT_$(basename "${ALGO_FILE}" | tr -c '[:alnum:]' '_' | tr '[:lower:]' '[:upper:]')"
fi

if grep -Fq "${ID_MARKER}" "${TARGET_FILE}"; then
  echo "Ignorado: marcador '${ID_MARKER}' já presente em ${TARGET_FILE}."
  exit 0
fi

if ! grep -Fq "${ANCHOR}" "${TARGET_FILE}"; then
  echo "Erro: âncora '${ANCHOR}' não encontrada em ${TARGET_FILE}." >&2
  exit 1
fi

BACKUP_FILE="${TARGET_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
cp -p "${TARGET_FILE}" "${BACKUP_FILE}"

python3 - "${TARGET_FILE}" "${ANCHOR}" "${ALGO_FILE}" "${POSITION}" "${ID_MARKER}" << 'PY_INJECT'
import sys
from pathlib import Path

target_path = Path(sys.argv[1])
anchor = sys.argv[2]
algo_path = Path(sys.argv[3])
position = sys.argv[4]
marker = sys.argv[5]

original = target_path.read_text(encoding="utf-8")
algo_code = algo_path.read_text(encoding="utf-8").rstrip("\n")

wrapped_block = (
    f"# BEGIN {marker}\n"
    f"{algo_code}\n"
    f"# END {marker}\n"
)

out_lines = []
injected = False

for line in original.splitlines(keepends=True):
    if not injected and anchor in line:
        if position == "--before":
            out_lines.append(wrapped_block)
            out_lines.append(line)
        else:
            out_lines.append(line)
            out_lines.append("\n" + wrapped_block)
        injected = True
    else:
        out_lines.append(line)

if not injected:
    raise RuntimeError(f"Âncora não localizada: {anchor}")

target_path.write_text("".join(out_lines), encoding="utf-8", newline="\n")
PY_INJECT

case "${TARGET_FILE}" in
  *.py) python3 -m py_compile "${TARGET_FILE}" ;;
  *.sh|*.bash) bash -n "${TARGET_FILE}" ;;
esac

echo "Sucesso: bloco '${ID_MARKER}' injetado em ${TARGET_FILE} (backup: ${BACKUP_FILE})."
