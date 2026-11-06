#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/ci.sh
./scripts/fuzz.sh 60
./scripts/timing.sh
./scripts/coverage.sh
./scripts/mutation.sh
