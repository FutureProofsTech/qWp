#!/usr/bin/env bash
# Prepare and run the long combined fuzz soak.
#
# Default: 72 hours (259,200 s), one continuous process, all qWp versions.
# The run is pinned to a clean git commit and records commit, binary hash,
# host, start/end, exit status, and the fuzz log.
#
# Smoke test:
#   SOAK_SECONDS=60 ./scripts/soak-72h.sh
#
# Full run:
#   ./scripts/soak-72h.sh
#
# Environment:
#   SOAK_HOURS=72          duration in hours (default 72)
#   SOAK_SECONDS=<n>       explicit duration override
#   SOAK_SEED=0x...        PRNG seed (default fixed, reproducible)
#   SOAK_LOG=<path>        log path
#   SOAK_ALLOW_DIRTY=1     allow a dirty working tree (not for release evidence)
set -euo pipefail

cd "$(dirname "$0")/.."

hours="${SOAK_HOURS:-72}"
seconds="${SOAK_SECONDS:-$((hours * 3600))}"
seed="${SOAK_SEED:-0x9e3779b97f4a7c15}"
commit="$(git rev-parse HEAD)"
short_commit="$(git rev-parse --short=12 HEAD)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log="${SOAK_LOG:-/tmp/opencode/qwp-soak-72h-${short_commit}-${stamp}.log}"
meta="${log}.meta"

if [ "${SOAK_ALLOW_DIRTY:-0}" != "1" ] && [ -n "$(git status --porcelain)" ]; then
  echo "soak: working tree is dirty; commit or set SOAK_ALLOW_DIRTY=1" >&2
  exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "soak: cargo not found" >&2
  exit 2
fi

echo "== building release fuzz driver =="
cargo build --release -p qwp-tests --bin fuzz

binary="target/release/fuzz"
if [ ! -x "$binary" ]; then
  echo "soak: $binary not found" >&2
  exit 2
fi
binary_sha="$(sha256sum "$binary" | awk '{print $1}')"
start="$(date -u +%FT%TZ)"

{
  echo "qWp long fuzz soak"
  echo "commit=$commit"
  echo "binary=$binary"
  echo "binary_sha256=$binary_sha"
  echo "host=$(uname -a)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "seconds=$seconds"
  echo "seed=$seed"
  echo "start_utc=$start"
  echo "log=$log"
  echo "---"
} | tee "$meta"

status=0
run() {
  if command -v taskset >/dev/null 2>&1; then
    taskset -c 1 "$binary" "$seconds" "$seed"
  else
    "$binary" "$seconds" "$seed"
  fi
}

set +e
run 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
set -e

end="$(date -u +%FT%TZ)"
{
  echo "---"
  echo "end_utc=$end"
  echo "exit=$status"
} | tee -a "$meta" >>"$log"

if [ "$status" -eq 0 ] && grep -q 'panics=0' "$log"; then
  echo "SOAK PASSED: commit=$commit seconds=$seconds log=$log"
  exit 0
fi

echo "SOAK FAILED: commit=$commit exit=$status log=$log" >&2
exit "$status"
