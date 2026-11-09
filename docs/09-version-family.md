# qWp QHS Version Family

**Status:** Design baseline for versioned QHS variants.  
**Rule:** Every version gets its own ADR, proof, format version, domain contexts, cache context, KAT, tests, attack harness, Kani proofs, fuzz coverage, timing, and 1-hour soak. A version is never silently extended.

---

## 1. Design axes

The version family is organized around six axes:

1. **Stateful vs stateless** — can the signer keep a monotonic counter and never clone the key?
2. **Signatures per key** — 256 (QHS-1/2), 4,096 (QHS-3/3.1), or 2^20 (QHS-4 at the 128-bit target).
3. **Signature size** — 1.3–3.4 KB for hash-based stateful variants; 7–30 KB for stateless.
4. **Signing latency** — offline signing can tolerate hundreds of milliseconds; interactive services cannot.
5. **Quantum margin** — 128-bit classical / 64-bit quantum baseline; optional 256-bit quantum margin.
6. **Verifier profile** — server, bootloader, MCU, or long-term archive.

## 2. Version matrix

| Version | Construction | Stateful | Sigs/key | Signature | Keygen | Sign | Verify | Best use |
|---|---|---:|---:|---:|---:|---:|---:|---|
| **QHS-1** | b=4, h=8 | Yes | 256 | 2,408 B | 10–13 ms | 0.21–0.33 ms | 0.14 ms | speed-first offline signing |
| **QHS-2** | b=6, h=8 | Yes | 256 | 1,704 B | 27–28 ms | 0.46–0.61 ms | 0.41 ms | compact firmware/release signing |
| **QHS-3** | b=6, h=12 | Yes | 4,096 | 1,832 B | ≈0.40–0.44 s | ≈1.60–1.70 ms | ≈0.39 ms | high-volume release pipelines |
| **QHS-3.1** | b=6, h=12, tree cache | Yes | 4,096 | 1,832 B | ≈0.40–0.41 s | **≈0.35–0.36 ms** | ≈0.39 ms | high-volume signing with fast sign |
| **QHS-4** | stateless hypertree/FORS | No | ≤2^20 at 128-bit target | 18,216 B | ≈0.10 s | ≈0.81 s | ≈1.6 ms | concurrent/stateless signing |
| **QHS-4.1** | QHS-4 + parallel trees | No | ≤2^20 at 128-bit target | 18,216 B | ≈0.10 s | **≈0.11 s** | ≈1.6 ms | stateless signing with fast sign |
| QHS-5 (planned) | 512-bit hash, h=8 | Yes | 256 | ≈3.4 KB | ≈2× QHS-2 | ≈2× QHS-2 | ≈2× QHS-2 | 256-bit quantum margin |
| QHS-6 (planned) | QHS + classical hybrid | Yes | 256 | QHS + classical | QHS + classical | QHS + classical | QHS + classical | migration/compliance |
| QHS-E | QHS verifier profile | n/a | n/a | QHS-1/2/3/3.1 | n/a | n/a | same | bootloader/MCU verifier |

## 3. Decision guide

1. **Can the key stay stateful and single-writer?**
   - Yes → QHS-1/2/3/3.1.
   - No → QHS-4 (stateless); this is a major new design, not a parameter tweak.

2. **How many signatures per key?**
   - ≤256 → QHS-1 or QHS-2.
   - ≤4,096 → QHS-3 or QHS-3.1.
   - Stateless / no counter → QHS-4 (≤2^20 at the 128-bit target).
   - >4,096 stateful → QHS-3 with multiple keys, or QHS-4 when statelessness matters. A single tree beyond h=12 makes keygen/cache large.

3. **What matters more: size or speed?**
   - Speed → QHS-1.
   - Size → QHS-2.
   - Both, with more capacity → QHS-3.
   - More capacity and faster signing → QHS-3.1.
   - Stateless with fast signing → QHS-4.1.

4. **Do you need 256-bit quantum margin?**
   - No → QHS-1/2/3/3.1.
   - Yes → QHS-5 (new hash-output profile).

5. **Do you need standards, HSM, or classical hybrid?**
   - Hybrid → QHS-6.
   - Standards/HSM → a deployment profile and independent audit, not a new hash-based parameter set.

6. **Is the verifier a constrained MCU/bootloader?**
   - Use QHS-E: the same signatures, a no_std verifier profile, code-size and stack benchmarks.

## 4. QHS-3: high-capacity stateful

QHS-3 is the next implemented version. It keeps the QHS-2 WOTS parameters and extends the Merkle tree from height 8 to height 12:

| Parameter | QHS-3 |
|---|---:|
| WOTS base | 64 |
| Chains | 45 × 63 steps |
| Merkle height | 12 |
| Leaves/signatures | 4,096 |
| Public key | 64 B |
| Private key | 64 B |
| Auth path | 384 B |
| Signature | **1,832 B** |
| Cache | 131,140 B (128 KiB leaves) |
| Keygen | ≈0.40–0.44 s |
| Cached sign | ≈1.60–1.70 ms |
| Verify | ≈0.39 ms |

QHS-3.1 is the tree-cache profile of QHS-3: identical keys, signature bytes,
KAT, capacity, and proof; signing drops to ≈0.35–0.36 ms using a 262,180-byte
tree cache. Use QHS-3.1 when signing latency matters; QHS-3 remains available.

Why h=12:

- 4,096 signatures per key is enough for years of CI/release activity.
- `next_leaf` still fits the 64-byte key format (`u16`, max 4,096).
- Keygen stays under a second with parallel leaf derivation.
- The cache is 128 KiB, acceptable for a host signer.
- The signature grows by only 128 bytes over QHS-2.

h=16 (65,536 signatures) would require a `u32` counter and a 2 MiB cache; h=12 is the better first high-capacity step.

## 5. QHS-4: stateless hypertree/FORS

QHS-4 is implemented as a separate stateless construction, not a parameter tweak:

| Parameter | QHS-4 |
|---|---:|
| WOTS | 45 × 63, 43+2 base-64 digits |
| Hypertree | 8 layers × height 8, total h=64 |
| FORS | 16 trees × height 8 |
| Public key | 68 B |
| Private key | 68 B |
| Signature | **18,216 B** |
| Keygen | ≈0.19 s |
| Stateless sign | ≈1.51 s |
| Verify | ≈3.0 ms |
| Security target | 128-bit classical / ≥64-bit quantum for q ≤ 2^20 |

QHS-4 has no counter, no cache, and no state guard. It is the right profile when
the signer cannot maintain a single-writer monotonic counter. The trade-off is a
large signature and slower signing. The proof and limits are in
`docs/13-qhs4.md`; the ADR is `docs/adr/0006-qhs4-stateless.md`. The QHS-4
1-hour soak passed with 91,191,782 iterations and 0 panics.

QHS-4.1 is the fast-signing profile of QHS-4. It uses the same 68-byte keys,
the same 18,216-byte signature, the same proof, and the same `q ≤ 2^20` bound.
Only the implementation changes: reusable BLAKE3 derive-key contexts and
parallel hypertree/FORS tree generation. Signing drops from ≈0.81 s to ≈0.11 s
on the reference host (≈7.4×); the sequential `Qhs4PrivateKey::sign` remains the
reference and fallback. The `qhs41-*` CLI commands use the parallel path, and
`qhs4-verify` / `qhs41-verify` accept the same signatures.

QHS-4.1 does not replace QHS-1/2/3/3.1 or QHS-4. All versions remain available
and version-separated.

## 6. QHS-5: 256-bit quantum margin (planned)

QHS-5 would use a 512-bit hash output (or a 512-bit mode built from BLAKE3 XOF):

- WOTS chains: 45 × 64 B = 2,880 B;
- auth path: 8 × 64 B = 512 B;
- signature: ≈3,400 B;
- roughly 2× hashing cost;
- 256-bit classical / 128-bit quantum margin.

This requires a 64-byte hash mode and a new proof/format version.

## 7. QHS-6: classical hybrid (planned)

A hybrid would carry both a QHS signature and a classical signature (for example Ed25519 or RSA). Verification accepts only if both verify. This provides migration safety but requires a classical implementation and a new hybrid proof. It is not part of the zero-dependency hash-only core unless the classical primitive is also in-tree.

## 8. QHS-E: embedded verifier profile

QHS-E is not a new signature. It is a `no_std` verifier profile of QHS-1/2/3/3.1 with:

- fixed-size stack usage;
- no heap;
- code-size and cycle benchmarks on constrained targets;
- the same public keys and signatures.

## 9. Release rule

Each signature version is independently gated:

1. ADR accepted.
2. Proof written and reviewed.
3. Format version and domain contexts fixed.
4. KAT, unit, integration, attack, Kani, fuzz, timing, mutation, coverage.
5. 1-hour soak on the exact release commit.
6. Versioned tag; older versions remain available.

Profiles such as QHS-3.1 and QHS-4.1 share the base signature version, proof,
KAT, and signature bytes. They still get their own ADR, implementation tests,
timing, and release tag.
