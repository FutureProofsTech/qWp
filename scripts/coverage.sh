#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo llvm-cov --workspace --all-features --summary-only
cargo llvm-cov --release -p qwp-crypto --lib --summary-only
