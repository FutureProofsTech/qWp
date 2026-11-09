#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo build -p qwp-bench --release --bin qwp-timing --bin qhs2_timing --bin qhs3_timing --bin qhs31_timing --bin qhs4_timing
./target/release/qwp-timing
./target/release/qhs2_timing
./target/release/qhs3_timing
./target/release/qhs31_timing
./target/release/qhs4_timing
