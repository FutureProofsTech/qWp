#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo mutants -p qwp-core --in-place --timeout 120
cargo mutants -p qwp-crypto --in-place --timeout 180
cargo mutants -p qwp-platform --in-place --timeout 120
cargo mutants -p qwp-cli --in-place --timeout 180
cargo mutants -p qwp-crypto --file crates/qwp-crypto/src/qhs4.rs --in-place --timeout 90 --cargo-test-arg qhs4 --output mutants-qhs4.out
