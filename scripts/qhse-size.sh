#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for target in thumbv7em-none-eabihf riscv32imac-unknown-none-elf; do
  cargo build --manifest-path crates/qwp-e-size/Cargo.toml --release --target "$target"
  lib="crates/qwp-e-size/target/$target/release/libqwp_e_size.a"
  dir="$(mktemp -d)"
  (
    cd "$dir"
    ar x "$OLDPWD/$lib"
    printf '%s: ' "$target"
    find . -maxdepth 1 -type f \
      \( -name 'qwp_e_size*' -o -name 'qwp_e-*' -o -name 'qwp_hash*' -o -name 'qwp_core*' \) \
      -print0 \
      | xargs -0 llvm-size -A \
      | awk '$1 ~ /^\.text/ {t+=$2} $1 ~ /^\.rodata/ {r+=$2} END {printf "text=%d rodata=%d total=%d\n", t, r, t+r}'
  )
  rm -rf "$dir"
done
