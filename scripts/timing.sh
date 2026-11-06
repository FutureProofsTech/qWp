#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo build -p qwp-bench --release --bin qwp-timing
if command -v taskset >/dev/null 2>&1; then
    taskset -c 0 ./target/release/qwp-timing
else
    ./target/release/qwp-timing
fi
