#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --all -- --check

echo "== clippy =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== tests =="
cargo test --workspace --all-features

echo "== release tests =="
cargo test --workspace --release

echo "== attacks =="
cargo run -p qwp-attacks --bin attack-suite

echo "== fuzz =="
cargo run -q -p qwp-tests --release --bin fuzz -- 5

echo "== audit =="
cargo run -p qwp-attacks --bin audit

echo "== zero dependencies =="
cargo tree --workspace --edges normal,build,dev

echo "== safe Rust gate =="
grep -RIn 'forbid(unsafe_code)' crates --include='*.rs'
if grep -RInE 'unsafe[[:space:]]*\{|unsafe[[:space:]]+(fn|impl|trait)|asm!|global_asm!|transmute|from_raw_parts|static[[:space:]]+mut|#\[no_mangle\]' crates --include='*.rs'; then
    echo "unsafe construct found" >&2
    exit 1
fi

echo "ci: ok"
