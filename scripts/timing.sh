#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo build -p qwp-bench --release --bin qwp-timing
./target/release/qwp-timing
