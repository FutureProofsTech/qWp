# qWp Attack Trees

**Rule:** Every critical asset has an attack tree; every leaf maps to an abuse case, attack harness, and gap if unresolved.

**Scope:** §1–§6 cover the legacy braid research path. §7–§15 cover the production QHS-1/2/3/3.1/4, QHS-4.1, QHS-4.2, QHS-5, and QHS-6 signatures.

## 1. Signature forgery

```
Forge a signature
├── Use identity private key
│   └── S = M; verify accepts (C1)                 [BL-0001, closed — rejected]
├── Find an equivalent braid with same invariant
│   ├── Polynomial inversion                       [GAP-CRYPTO-0006]
│   └── Collision search                           [GAP-CRYPTO-0006]
├── Recover private key
│   ├── Brute force 14^32                          [GAP-CRYPTO-0005]
│   ├── Garside/conjugacy attack                   [GAP-CRYPTO-0005]
│   └── Length-based/summit-set attack             [GAP-CRYPTO-0005]
├── Exploit malleability
│   ├── Replay signature in another context        [domain separation]
│   └── Change encoding without changing semantics [canonicalization]
└── Exploit implementation
    ├── Parser confusion                           [GAP-FMT-0007, closed]
    ├── Fault injection                            [GAP-CRYPTO-0014, closed]
    └── Timing leak                                [GAP-SIGN-0019, timing evidence]
```

## 2. Key recovery

```
Recover private braid
├── Entropy weakness
│   ├── Biased mapping                             [GAP-KEY-0008]
│   ├── Rejection timing leak                      [GAP-KEY-0008]
│   └── RNG failure                                [hardware]
├── Public polynomial inversion
│   ├── Heuristic state-tree search                [GAP-CRYPTO-0006]
│   └── Meet-in-the-middle                         [GAP-CRYPTO-0005]
└── Side channel
    ├── Branch timing                              [GAP-CRYPTO-0001]
    ├── Memory access pattern                      [GAP-CRYPTO-0001]
    └── Power/EM (out of scope, documented)        [D3]
```

## 3. Solver denial of service

```
Exhaust solver resources
├── Max crossings / worst-case branching            [GAP-SOLVER-0004]
├── Stack overflow                                  [Kani bound]
├── Integer overflow                                [checked arithmetic]
├── Polynomial buffer overflow                      [GAP-FMT-0003]
└── Algorithmic complexity attack                   [TL DP fixed loops]
```

## 4. Hash / parser

```
Break hash-to-braid
├── Collision in BLAKE3                             [assumption]
├── Collision in base-14 mapping                    [D16 full digest]
├── Malformed signature/public key                  [parser harness]
├── Non-canonical encoding                          [format spec]
└── Length extension                                [BLAKE3 not length-extendable]
```

## 5. Keygen / entropy

```
Break keygen
├── Weak RNG                                       [OS CSPRNG; no user-space health tests]
├── Rejection bias                                 [GAP-KEY-0008]
├── Degenerate braid accepted                      [runtime predicate]
├── Timing leak of rejection count                 [fixed attempts/CT]
└── Key collision                                  [key space analysis]
```

## 6. Timing / side channel

```
Leak secret
├── Secret-dependent branch                        [CT design]
├── Secret-dependent memory index                  [CT design]
├── Variable-time division                         [public modulus]
├── Compiler-introduced branch                     [code review + timing]
└── Cache/timing noise                             [Welch t-test harness]
```

Every leaf must have an attack harness or a documented reason in the gap register.

## 7. QHS-1 signature

```
Forge QHS-1
├── Used leaf, different message
│   ├── Decrease a WOTS digit                 [Lemma 1]
│   └── Find preimage/collision                [assumption]
├── Unused leaf
│   ├── Key-only WOTS forgery                  [Lemma 2]
│   └── Merkle path collision                  [Lemma 3]
├── Leaf reuse / counter rollback              [CLI lock + atomic counter + state guard]
├── Auth path / leaf index tampering           [attack suite]
├── Cache poisoning / foreign cache            [fingerprint + keyed MAC; verifier root]
└── Checksum/parser confusion                  [parser tests]
```

## 8. QHS-2 signature

```
Forge QHS-2
├── Used leaf, different message
│   ├── Decrease a base-64 WOTS digit          [Lemma 1]
│   └── Find preimage/collision                [assumption]
├── Unused leaf
│   ├── Key-only WOTS forgery                  [Lemma 2]
│   └── Merkle path collision                  [Lemma 3]
├── Leaf reuse / counter rollback              [CLI lock + atomic counter + state guard]
├── Auth path / leaf index tampering           [attack suite]
├── Cache poisoning / foreign cache            [versioned fingerprint + keyed MAC; verifier root]
├── QHS-1/QHS-2 cross-version confusion        [versioned formats/contexts; CLI tests]
└── Checksum/parser confusion                  [parser tests]
```

## 9. QHS-3 signature

```
Forge QHS-3
├── Used leaf, different message
│   ├── Decrease a base-64 WOTS digit          [Lemma 1]
│   └── Find preimage/collision                [assumption]
├── Unused leaf
│   ├── Key-only WOTS forgery                  [Lemma 2]
│   └── Merkle path collision                  [Lemma 3]
├── Leaf reuse / counter rollback              [CLI lock + atomic counter + state guard]
├── Auth path / leaf index tampering           [attack suite]
├── Cache poisoning / oversized cache          [versioned fingerprint + keyed MAC; bounded reads]
├── QHS-1/QHS-2/QHS-3/QHS-3.1 cross-version    [versioned formats/contexts; CLI tests]
└── Checksum/parser confusion                  [parser tests]
```

## 10. QHS-3.1 tree-cache profile

```
Attack QHS-3.1
├── Poisoned leaves or internal nodes           [versioned fingerprint + keyed MAC; verifier root]
├── Foreign tree cache                          [QHS-3.1 fingerprint context]
├── Oversized/special tree cache                [bounded reads]
├── Wrong tree for leaf index                   [auth-path extraction bounds; unit tests]
└── Signature semantics                         [same QHS-3 signature/proof]
```

## 11. QHS-4 stateless signature

```
Forge QHS-4
├── FORS few-time forgery
│   ├── Hit a used bottom leaf (64-bit idx)     [q/2^64]
│   ├── Hit revealed leaves in all 16 trees     [(γ/256)^16]
│   └── Combine                                  [q · 2^-192; 2^-172 at q=2^20]
├── WOTS fixed-message forgery
│   ├── Different child root under same key     [preimage/second-preimage]
│   └── Reuse with different value              [forbidden by fixed child root]
├── Hypertree path reuse
│   ├── 64-bit idx collision                    [q^2/2^65 ≤ 2^-25]
│   └── FORS reuse after collision              [2^-25 · 2^-112 = 2^-137]
├── Merkle/FORS path collision                  [128-bit hash collision bound]
├── Auth path / header / checksum tampering     [attack suite; Kani length proof]
├── Wrong message/key                           [attack suite]
├── Cross-version confusion                     [68-byte keys, 18,216-byte signature, header]
├── Stateless key mutation                      [CLI test: key bytes/mtime unchanged]
└── Timing/fault/DoS                            [Welch t-test; fixed loops]
```

## 12. QHS-4.1 parallel fast-signing profile

```
Attack QHS-4.1
├── Parallel/sequential divergence               [byte-equality tests; KAT]
├── Wrong/mismatched plan or tree                [sign_with_trees re-derives plan; selected path checks]
├── Worker failure                               [join error -> InternalFailure]
├── Timing/scheduling                            [Welch |t| < 4.5]
└── Signature semantics                          [same QHS-4 signature/proof/format]
```

## 14. QHS-5 512-bit stateful signature

```
Forge QHS-5
├── Message-digit collision                      [86 base-64 digits bind 512 bits; ~2^256]
├── WOTS one-time forgery                        [89×63 loss; preimage ~2^499.5]
├── Checksum manipulation                        [3 base-64 digits; C = Σ(63 − d_k)]
├── Merkle collision                             [512-bit output; ~2^256 classical / 2^128 quantum]
├── Merkle second preimage                       [~2^512 classical]
├── Leaf reuse / counter rollback                [state guard; guard > key refused]
├── Auth path/header/checksum tampering          [attack suite; Kani parser proofs]
├── Wrong message/key                            [attack suite]
├── Cross-version with QHS-1/2/3/4/4.2           [header [6,6,8,0]; 6,216-byte length]
├── Cache corruption / foreign cache             [fingerprint + keyed MAC; recompute]
└── Timing/fault/DoS                             [Welch |t| < 4.5; cached-leaf signing]
```

## 15. QHS-6 QHS-5 + Ed25519 hybrid

```
Forge QHS-6
├── Mix QHS-5 and Ed25519 components              [transcript binds both keys + message]
├── Break QHS-5 component                         [256-bit classical / ~128-bit quantum]
├── Break Ed25519 component                       [~128-bit classical; quantum-broken]
├── Break both components                         [required for a hybrid forgery]
├── Transcript collision                          [~2^256 classical / ~2^128 quantum]
├── Tamper QHS-5 or Ed25519 component             [attack suite; Kani length proofs]
├── Non-canonical Ed25519 S / invalid point       [strict S < L; canonical decode]
├── Small-order Ed25519 point                     [rejected by parser/verifier]
├── Leaf reuse / counter rollback                 [state guard; guard > key refused]
├── Cache corruption / foreign cache              [fingerprint + keyed MAC; recompute]
├── Cross-version with QHS-5 / Ed25519-only       [header [7,7,8,0]; 6,284-byte length]
└── Timing/fault/DoS                              [Welch |t| < 4.5]
```
