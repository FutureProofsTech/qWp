# Tooling-only workspaces

These directories are **not** part of the qWp production workspace. They are
standalone Cargo workspaces that pull external verification/test crates only for
evidence. The production crates in `crates/` remain zero-dependency and
`no_std` where required.

| Directory | Tool | Purpose |
|---|---|---|
| `fuzz/` | cargo-fuzz / libFuzzer | QHS-E verifier and signature-parser fuzzing |
| `tools/proptest-suite/` | proptest | property tests for QHS-E and signature parsers |
| `tools/loom-model/` | loom | model of the parallel leaf chunk/join protocol |
| `tools/dudect-suite/` | dudect-bencher | Welch t-test timing probes |
| `tools/aorai-model/` | Frama-C AORAI | illustrative C state-machine model of the QHS-E verification order |
| `tools/creusot-proofs/` | Creusot | contracts for QHS-E digit/checksum/Merkle bounds |

Run them with `../scripts/tooling.sh` from the repository root. The results are
recorded under `docs/evidence/qhse-*.txt`.

Creusot needs `cargo creusot config --update` once to add the local
`creusot-std` patch to `~/.cargo/config.toml`. The tooling script does this.
Remove that patch afterwards if you do not want it to affect other builds.

`tools/aorai-model` is a C model, not the Rust verifier. AORAI cannot analyze
Rust; it is used only to exercise the temporal ordering property. The Rust
implementation is verified by Kani, differential tests, proptest, libFuzzer, and
the attack suite.
