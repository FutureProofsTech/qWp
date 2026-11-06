#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

seconds="${1:-30}"
cargo run -q -p qwp-tests --release --bin fuzz -- "$seconds"
