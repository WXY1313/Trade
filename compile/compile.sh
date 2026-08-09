#!/usr/bin/env bash

set -euo pipefail

name="Trade"
contract_dir="./contract"

if ! command -v solc >/dev/null 2>&1; then
  echo "Error: solc is not installed or not in PATH." >&2
  exit 1
fi

if command -v abigen >/dev/null 2>&1; then
  abigen_cmd=$(command -v abigen)
else
  abigen_cmd="$(go env GOPATH)/bin/abigen"
fi
if [[ ! -x "$abigen_cmd" ]]; then
  echo "Error: abigen is not installed or not in PATH." >&2
  exit 1
fi

solc --evm-version paris --optimize --via-ir --abi --bin \
  "$contract_dir/$name.sol" -o "$contract_dir" --overwrite

"$abigen_cmd" \
  --abi="$contract_dir/$name.abi" \
  --bin="$contract_dir/$name.bin" \
  --pkg=contract \
  --out="$contract_dir/$name.go"

echo "Generated $contract_dir/$name.abi, $name.bin, and $name.go"
