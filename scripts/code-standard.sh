#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

full="${1:-}"

echo "== format =="
cargo fmt --all -- --check

echo "== clippy =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== release tests =="
cargo test --workspace --release

echo "== dependency isolation =="
external="$(cargo tree --workspace --edges normal --prefix none | grep -v '^qwp-' | grep -v '^$' || true)"
if [ -n "$external" ]; then
  echo "external dependency found:"
  echo "$external"
  exit 1
fi
echo "workspace crates only"

echo "== unsafe code =="
if grep -RInE 'unsafe[[:space:]]*\{|unsafe[[:space:]]+fn|unsafe[[:space:]]+impl' \
  --include='*.rs' crates >/tmp/qwp-unsafe.txt; then
  cat /tmp/qwp-unsafe.txt
  exit 1
fi
echo "no unsafe code"

echo "== Kani =="
cargo kani -p qwp-verify

if [ "$full" = "--full" ]; then
  echo "== QHS-E code size =="
  ./scripts/qhse-size.sh

  echo "== QHS-E timing =="
  cargo run -q -p qwp-bench --release --bin qhse_timing

  echo "== coverage (crypto core) =="
  cargo llvm-cov --release -p qwp-crypto --lib --summary-only

  echo "== coverage (classical) =="
  cargo llvm-cov --release -p qwp-classical --summary-only

  echo "== coverage (QHS-E) =="
  cargo llvm-cov --release -p qwp-e --summary-only
fi

echo "code-standard checks: ok"
