#!/usr/bin/env bash
# Publish or rotate a discovery-server Nym address into the KV store
# backing the worker in worker.js.
#
# Required env vars:
#   CF_API_TOKEN         Cloudflare API token (KV:Edit scope)
#   CF_ACCOUNT_ID        Cloudflare account ID
#   CF_KV_NAMESPACE_ID   KV namespace ID bound as DISCOVERY_KV in the worker
#
# Optional env vars:
#   DISCOVERY_DOMAIN     Domain serving the worker (e.g. example.com).
#                        If set, the script verifies the published address
#                        by hitting https://api.<domain>/api/v1/address.
#
# Usage:
#   ./set-address.sh <nym-address>
#   ./set-address.sh --from-server-log /path/to/nymstr-server.log
#   ./set-address.sh --show
set -euo pipefail

: "${CF_API_TOKEN:?CF_API_TOKEN not set}"
: "${CF_ACCOUNT_ID:?CF_ACCOUNT_ID not set}"
: "${CF_KV_NAMESPACE_ID:?CF_KV_NAMESPACE_ID not set}"

API="https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}/values/address"
AUTH=(-H "Authorization: Bearer ${CF_API_TOKEN}")

validate_address() {
  # Nym address format: base58.base58@base58 — permissive check.
  if ! [[ "$1" =~ ^[1-9A-HJ-NP-Za-km-z]+\.[1-9A-HJ-NP-Za-km-z]+@[1-9A-HJ-NP-Za-km-z]+$ ]]; then
    echo "error: '$1' does not look like a Nym address (expected id.key@gateway)" >&2
    exit 2
  fi
}

show() {
  curl -fsS "${AUTH[@]}" "$API" || { echo "(not set)"; return; }
  echo
}

put() {
  local addr="$1"
  validate_address "$addr"
  echo "publishing: $addr"
  curl -fsS -X PUT "${AUTH[@]}" \
    -H "Content-Type: text/plain" \
    --data-binary "$addr" \
    "$API" | grep -q '"success":true' && echo "ok"

  if [[ -n "${DISCOVERY_DOMAIN:-}" ]]; then
    local verify_url="https://api.${DISCOVERY_DOMAIN}/api/v1/address"
    echo "verifying at ${verify_url} ..."
    sleep 2
    curl -fsS "$verify_url" || echo "(not reachable yet — Cloudflare edge may take ~30s)"
    echo
  fi
}

case "${1:-}" in
  "")        echo "usage: $0 <nym-address> | --from-server-log <path> | --show" >&2; exit 1 ;;
  --show)    show ;;
  --from-server-log)
    [[ -n "${2:-}" ]] || { echo "missing log path" >&2; exit 1; }
    addr=$(grep -oE '[1-9A-HJ-NP-Za-km-z]+\.[1-9A-HJ-NP-Za-km-z]+@[1-9A-HJ-NP-Za-km-z]+' "$2" | tail -n1)
    [[ -n "$addr" ]] || { echo "no address found in $2" >&2; exit 1; }
    put "$addr"
    ;;
  *)         put "$1" ;;
esac
