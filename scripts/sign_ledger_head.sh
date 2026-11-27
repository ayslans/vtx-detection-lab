#!/usr/bin/env bash
set -euo pipefail

LEDGER_PATH="${1:-out/enriched/evidence_ledger.jsonl}"
SIG_PATH="${2:-out/enriched/evidence_ledger.head.sig.json}"
KEY_PATH="${3:-${VTX_LEDGER_SIGNING_KEY_PATH:-config/ledger_signing_ed25519.pem}}"
SIGNER_ID="${4:-${VTX_LEDGER_SIGNER_ID:-vtx-detection-lab}}"

if [ ! -s "${LEDGER_PATH}" ]; then
  echo "ERRO: ledger vazio ou inexistente: ${LEDGER_PATH}" >&2
  exit 1
fi

if [ ! -s "${KEY_PATH}" ]; then
  echo "ERRO: chave privada Ed25519 não encontrada em: ${KEY_PATH}" >&2
  echo "Gere com: openssl genpkey -algorithm Ed25519 -out ${KEY_PATH} && chmod 600 ${KEY_PATH}" >&2
  exit 1
fi

python3 - "${LEDGER_PATH}" "${SIG_PATH}" "${KEY_PATH}" "${SIGNER_ID}" << 'PY_SIGN'
import base64
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ledger_path = Path(sys.argv[1])
sig_path = Path(sys.argv[2])
key_path = Path(sys.argv[3])
signer_id = sys.argv[4]

lines = [
    ln.strip()
    for ln in ledger_path.read_text(encoding="utf-8").splitlines()
    if ln.strip()
]
if not lines:
    raise SystemExit(f"Ledger sem entradas: {ledger_path}")

entries = [json.loads(ln) for ln in lines]
last_entry = entries[-1]
head_hash = last_entry["entry_hash"]
asset_id = last_entry.get("asset_id")

private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
if not isinstance(private_key, Ed25519PrivateKey):
    raise SystemExit("A chave privada deve ser do tipo Ed25519.")

public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

claim = {
    "schema": "vtx-ledger-head-attestation-v1",
    "ledger_path": ledger_path.as_posix(),
    "head_hash": head_hash,
    "entry_count": len(entries),
    "asset_id": asset_id,
    "signer_id": signer_id,
    "signed_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "algorithm": "Ed25519",
}

canonical = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")
digest_to_sign = b"vtx-ledger-head-v1:" + hashlib.sha256(canonical).digest()
signature = private_key.sign(digest_to_sign)

attestation = {
    **claim,
    "signature_b64": base64.b64encode(signature).decode("ascii"),
    "public_key_pem": public_pem,
}

sig_path.parent.mkdir(parents=True, exist_ok=True)
sig_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
print(f"Assinado head_hash={head_hash} (entries={len(entries)}) -> {sig_path}")
PY_SIGN
