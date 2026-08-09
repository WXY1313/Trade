#!/usr/bin/env bash

set -euo pipefail

if command -v ganache >/dev/null 2>&1; then
  ganache_cmd=ganache
elif command -v ganache-cli >/dev/null 2>&1; then
  ganache_cmd=ganache-cli
else
  echo "Error: Ganache is not installed." >&2
  exit 1
fi

output_file=$(mktemp "${TMPDIR:-/tmp}/trade-ganache.XXXXXX")
env_file=$(mktemp "${TMPDIR:-/tmp}/trade-env.XXXXXX")
ganache_pid=""

cleanup() {
  status=$?
  if [[ -n "$ganache_pid" ]] && kill -0 "$ganache_pid" 2>/dev/null; then
    kill "$ganache_pid" 2>/dev/null || true
    wait "$ganache_pid" 2>/dev/null || true
  fi
  rm -f "$output_file" "$env_file"
  exit "$status"
}
trap cleanup EXIT

"$ganache_cmd" --mnemonic "Trade" --server.port 18545 >"$output_file" 2>&1 &
ganache_pid=$!

for _ in {1..30}; do
  grep -q "Private Keys" "$output_file" && break
  if ! kill -0 "$ganache_pid" 2>/dev/null; then
    echo "Error: Ganache exited before producing accounts:" >&2
    sed -n '1,120p' "$output_file" >&2
    exit 1
  fi
  sleep 0.2
done

awk '
  /Available Accounts/ { section="accounts"; next }
  /Private Keys/       { section="keys"; next }
  /HD Wallet/          { section="" }
  section == "accounts" && match($0, /0x[[:xdigit:]]+/) && RLENGTH == 42 {
    accounts[++account_count] = substr($0, RSTART, RLENGTH)
  }
  section == "keys" && match($0, /0x[[:xdigit:]]+/) && RLENGTH == 66 {
    keys[++key_count] = substr($0, RSTART + 2, RLENGTH - 2)
  }
  END {
    if (account_count == 0 || account_count != key_count) exit 1
    for (i = 1; i <= account_count; i++) print "ACCOUNT_" i "=" accounts[i]
    for (i = 1; i <= key_count; i++) print "PRIVATE_KEY_" i "=" keys[i]
  }
' "$output_file" >"$env_file" || {
  echo "Error: Could not extract Ganache accounts and private keys." >&2
  exit 1
}

mv "$env_file" .env
echo "Generated .env with $(grep -c '^PRIVATE_KEY_' .env) private keys."
