#!/usr/bin/env bash
# Run the optional verification/test tooling.
#
# These tools use external crates in standalone workspaces. They are not
# production dependencies and do not affect the zero-dependency workspace.
set -euo pipefail

cd "$(dirname "$0")/.."

fuzz_seconds="${FUZZ_SECONDS:-30}"
nightly="${NIGHTLY:-nightly-2026-08-21}"

echo "== libFuzzer: QHS-E verifier (${fuzz_seconds}s) =="
cargo "+${nightly}" fuzz run qhse_verify -- "-max_total_time=${fuzz_seconds}"

echo "== libFuzzer: signature parsers (${fuzz_seconds}s) =="
cargo "+${nightly}" fuzz run qhs_parse -- "-max_total_time=${fuzz_seconds}"
cargo "+${nightly}" fuzz run qhs6_parse -- "-max_total_time=${fuzz_seconds}"

echo "== proptest =="
(
  cd tools/proptest-suite
  cargo test --release
)

echo "== loom =="
(
  cd tools/loom-model
  LOOM_MAX_PREEMPTIONS=2 cargo test --release
)

echo "== dudect =="
(
  cd tools/dudect-suite
  cargo build --release --bin qhse_dudect
  if command -v taskset >/dev/null 2>&1; then
    taskset -c 1 ./target/release/qhse_dudect
  else
    ./target/release/qhse_dudect
  fi
)

echo "== Creusot =="
(
  cd tools/creusot-proofs
  cargo creusot config --update
  cargo creusot
)

echo "== AORAI (C model) =="
(
  cd tools/aorai-model
  frama-c qhse_state.c -aorai-automata qhse_state.ya \
    -then-last -wp -wp-rte -wp-timeout 60 -wp-prover alt-ergo,z3
)

echo "== cargo-show-asm =="
for function in verify_common wots_verify message_digits leaf_hash node_hash signature_checksum; do
  cargo asm -p qwp-e --lib --release "$function" >/dev/null
  printf 'asm: %s ok\n' "$function"
done

echo "tooling checks: ok"
