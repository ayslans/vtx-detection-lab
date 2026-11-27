#!/usr/bin/env bash
set -euo pipefail

LEDGER_PATH="${1:-out/enriched/evidence_ledger.jsonl}"
SIG_PATH="${2:-out/enriched/evidence_ledger.head.sig.json}"
TRUSTED_PUB_PATH="${3:-${VTX_LEDGER_TRUSTED_PUB_PATH:-}}"

if [ ! -s "${LEDGER_PATH}" ]; then
  echo "ERRO: ledger vazio ou inexistente: ${LEDGER_PATH}" >&2
  exit 1
fi

if [ ! -s "${SIG_PATH}" ]; then
  echo "ERRO: atestado de assinatura não encontrado: ${SIG_PATH}" >&2
  exit 1
fi

python3 - "${LEDGER_PATH}" "${SIG_PATH}" "${TRUSTED_PUB_PATH}" << 'PY_VERIFY'
import base64
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ledger_path = Path(sys.argv[1])
sig_path = Path(sys.argv[2])
trusted_pub_arg = sys.argv[3]

lines = [
    ln.strip()
    for ln in ledger_path.read_text(encoding="utf-8").splitlines()
    if ln.strip()
]
if not lines:
    raise SystemExit(f"ERRO: ledger sem entradas: {ledger_path}")

entries = [json.loads(ln) for ln in lines]
current_head_hash = entries[-1]["entry_hash"]
current_entry_count = len(entries)

att = json.loads(sig_path.read_text(encoding="utf-8"))

if att.get("head_hash") != current_head_hash:
    raise SystemExit(
        f"ERRO: head_hash divergente (assinado={att.get('head_hash')} vs ledger={current_head_hash})"
    )

if att.get("entry_count") != current_entry_count:
    raise SystemExit(
        f"ERRO: entry_count divergente (assinado={att.get('entry_count')} vs ledger={current_entry_count})"
    )

if trusted_pub_arg:
    pub_bytes = Path(trusted_pub_arg).read_bytes()
else:
    pub_pem = att.get("public_key_pem")
    if not pub_pem:
        raise SystemExit("ERRO: chave pública confiável não informada e ausente no atestado.")
    pub_bytes = pub_pem.encode("utf-8")

public_key = serialization.load_pem_public_key(pub_bytes)
if not isinstance(public_key, Ed25519PublicKey):
    raise SystemExit("ERRO: chave pública não é Ed25519.")

claim = {
    k: v
    for k, v in att.items()
    if k not in {"signature_b64", "public_key_pem"}
}
canonical = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")
digest_to_sign = b"vtx-ledger-head-v1:" + hashlib.sha256(canonical).digest()
signature = base64.b64decode(att["signature_b64"])

try:
    public_key.verify(signature, digest_to_sign)
except Exception as exc:
    raise SystemExit(f"ERRO: assinatura Ed25519 inválida: {exc}") from exc

print(
    f"Assinatura Ed25519 VÁLIDA: head_hash={current_head_hash} "
    f"(entries={current_entry_count}, signer={att.get('signer_id')})"
)
PY_VERIFY
