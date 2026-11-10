//! In-house qWp fuzz driver.
//!
//! No external fuzzing crate. Deterministic PRNG, fixed time budget, panic
//! detection, and parser/verifier round-trip checks.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use qwp_classical::{Ed25519PrivateKey, Ed25519Signature};
use qwp_core::{BRAID_BYTES, Braid, PUBLIC_KEY_BYTES, Polynomial};
use qwp_crypto::{
    QHS_PRIVATE_KEY_BYTES, QHS_PUBLIC_KEY_BYTES, QHS_SIGNATURE_BYTES, QHS2_PRIVATE_KEY_BYTES,
    QHS2_PUBLIC_KEY_BYTES, QHS2_SIGNATURE_BYTES, QHS3_PRIVATE_KEY_BYTES, QHS3_PUBLIC_KEY_BYTES,
    QHS3_SIGNATURE_BYTES, QHS3_TREE_NODES, QHS4_PRIVATE_KEY_BYTES, QHS4_PUBLIC_KEY_BYTES,
    QHS4_SIGNATURE_BYTES, QHS5_PRIVATE_KEY_BYTES, QHS5_PUBLIC_KEY_BYTES, QHS5_SIGNATURE_BYTES,
    QHS6_PRIVATE_KEY_BYTES, QHS6_PUBLIC_KEY_BYTES, QHS6_SIGNATURE_BYTES, QHS42_PRIVATE_KEY_BYTES,
    QHS42_PUBLIC_KEY_BYTES, QHS42_SIGNATURE_BYTES, Qhs2PrivateKey, Qhs2PublicKey, Qhs2Signature,
    Qhs3PrivateKey, Qhs3PublicKey, Qhs3Signature, Qhs4PrivateKey, Qhs4PublicKey, Qhs4Signature,
    Qhs5PrivateKey, Qhs5PublicKey, Qhs5Signature, Qhs6PrivateKey, Qhs6PublicKey, Qhs6Signature,
    Qhs42PrivateKey, Qhs42PublicKey, Qhs42Signature, QhsPrivateKey, QhsPublicKey, QhsSignature,
    qhs_keygen, qhs2_keygen, qhs3_auth_path_from_tree, qhs3_build_tree, qhs3_keygen_from_leaves,
    qhs4_keygen, qhs5_keygen, qhs6_keygen, qhs42_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};
use qwp_platform::{qhs3_leaves_parallel, qhs4_sign_parallel, qhs42_sign_parallel};

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = u8::try_from(self.next() & 0xff).unwrap_or(0);
        }
    }
}

fn random_rounds(rng: &mut Rng) {
    for _ in 0..2 {
        let mut seed = [0_u8; 32];
        rng.fill(&mut seed);
        let Ok((mut private_key, public_key)) = qhs_keygen(&seed) else {
            eprintln!("fuzz: random qhs1 keygen failed");
            std::process::exit(2);
        };
        let Ok((mut private_key2, public_key2)) = qhs2_keygen(&seed) else {
            eprintln!("fuzz: random qhs2 keygen failed");
            std::process::exit(2);
        };
        let Ok(leaves) = qhs3_leaves_parallel(&seed) else {
            eprintln!("fuzz: random qhs3 leaves failed");
            std::process::exit(2);
        };
        let Ok((mut private_key3, public_key3)) = qhs3_keygen_from_leaves(&seed, &leaves) else {
            eprintln!("fuzz: random qhs3 keygen failed");
            std::process::exit(2);
        };
        let mut nodes = vec![[0_u8; 32]; QHS3_TREE_NODES];
        if qhs3_build_tree(&leaves, &mut nodes).is_err() {
            eprintln!("fuzz: random qhs31 tree failed");
            std::process::exit(2);
        }

        for _ in 0..4 {
            let length = usize::try_from(rng.next() % 257).unwrap_or(0);
            let mut message = [0_u8; 256];
            rng.fill(&mut message[..length]);
            let message = &message[..length];

            let Ok(signature) = private_key.sign(message) else {
                eprintln!("fuzz: random qhs1 sign failed");
                std::process::exit(2);
            };
            if public_key.verify(message, &signature).is_err() {
                eprintln!("fuzz: random qhs1 verify failed");
                std::process::exit(2);
            }
            let Ok(signature2) = private_key2.sign(message) else {
                eprintln!("fuzz: random qhs2 sign failed");
                std::process::exit(2);
            };
            if public_key2.verify(message, &signature2).is_err() {
                eprintln!("fuzz: random qhs2 verify failed");
                std::process::exit(2);
            }
            let Ok(signature3) = private_key3.sign_with_leaves(message, &leaves) else {
                eprintln!("fuzz: random qhs3 sign failed");
                std::process::exit(2);
            };
            if public_key3.verify(message, &signature3).is_err() {
                eprintln!("fuzz: random qhs3 verify failed");
                std::process::exit(2);
            }
            let Ok(auth_path) = qhs3_auth_path_from_tree(&leaves, &nodes, private_key3.next_leaf())
            else {
                eprintln!("fuzz: random qhs31 auth path failed");
                std::process::exit(2);
            };
            let Ok(signature31) = private_key3.sign_with_auth_path(message, &auth_path) else {
                eprintln!("fuzz: random qhs31 sign failed");
                std::process::exit(2);
            };
            if public_key3.verify(message, &signature31).is_err() {
                eprintln!("fuzz: random qhs31 verify failed");
                std::process::exit(2);
            }
        }
    }
}

fn fallback_qhs5_signature() -> Qhs5Signature {
    let mut bytes = [0_u8; QHS5_SIGNATURE_BYTES];
    bytes[0] = 6;
    bytes[1] = 6;
    Qhs5Signature::from_bytes(bytes)
}

fn main() {
    let seconds = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let rng_seed = std::env::args()
        .nth(2)
        .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    println!("fuzz: start seconds={seconds} seed=0x{rng_seed:016x}");
    let mut rng = Rng::new(rng_seed);
    let seed = [7_u8; 32];
    let Ok((mut private_key, public_key)) = qhs_keygen(&seed) else {
        eprintln!("fuzz: keygen failed");
        std::process::exit(2);
    };
    let Ok(valid_signature) = private_key.sign(b"fuzz-seed") else {
        eprintln!("fuzz: seed sign failed");
        std::process::exit(2);
    };
    if public_key.verify(b"fuzz-seed", &valid_signature).is_err() {
        eprintln!("fuzz: seed verify failed");
        std::process::exit(2);
    }
    let Ok((mut private_key2, public_key2)) = qhs2_keygen(&seed) else {
        eprintln!("fuzz: qhs2 keygen failed");
        std::process::exit(2);
    };
    let Ok(valid_signature2) = private_key2.sign(b"fuzz-seed-qhs2") else {
        eprintln!("fuzz: qhs2 seed sign failed");
        std::process::exit(2);
    };
    if public_key2
        .verify(b"fuzz-seed-qhs2", &valid_signature2)
        .is_err()
    {
        eprintln!("fuzz: qhs2 seed verify failed");
        std::process::exit(2);
    }
    let Ok(leaves3) = qhs3_leaves_parallel(&seed) else {
        eprintln!("fuzz: qhs3 leaves failed");
        std::process::exit(2);
    };
    let Ok((mut private_key3, public_key3)) = qhs3_keygen_from_leaves(&seed, &leaves3) else {
        eprintln!("fuzz: qhs3 keygen failed");
        std::process::exit(2);
    };
    let Ok(valid_signature3) = private_key3.sign_with_leaves(b"fuzz-seed-qhs3", &leaves3) else {
        eprintln!("fuzz: qhs3 seed sign failed");
        std::process::exit(2);
    };
    if public_key3
        .verify(b"fuzz-seed-qhs3", &valid_signature3)
        .is_err()
    {
        eprintln!("fuzz: qhs3 seed verify failed");
        std::process::exit(2);
    }
    let qhs4_keys = if seconds >= 30 {
        let Ok((private_key4, public_key4)) = qhs4_keygen(&seed) else {
            eprintln!("fuzz: qhs4 keygen failed");
            std::process::exit(2);
        };
        let Ok(valid_signature4) = qhs4_sign_parallel(&private_key4, b"fuzz-seed-qhs4") else {
            eprintln!("fuzz: qhs4 seed sign failed");
            std::process::exit(2);
        };
        if public_key4
            .verify(b"fuzz-seed-qhs4", &valid_signature4)
            .is_err()
        {
            eprintln!("fuzz: qhs4 seed verify failed");
            std::process::exit(2);
        }
        Some((private_key4, public_key4, valid_signature4))
    } else {
        None
    };
    let fallback_public4 = Qhs4PublicKey::from_root([0_u8; 32], [0_u8; 32]);
    let fallback_signature4 = Qhs4Signature::from_bytes([0_u8; QHS4_SIGNATURE_BYTES]);
    let (public_key4, valid_signature4) = qhs4_keys
        .as_ref()
        .map_or((&fallback_public4, &fallback_signature4), |keys| {
            (&keys.1, &keys.2)
        });
    if let Some((private_key4, _, _)) = &qhs4_keys
        && seconds >= 60
    {
        for _ in 0..4 {
            let length = usize::try_from(rng.next() % 257).unwrap_or(0);
            let mut message = [0_u8; 256];
            rng.fill(&mut message[..length]);
            let Ok(signature) = qhs4_sign_parallel(private_key4, &message[..length]) else {
                eprintln!("fuzz: random qhs4 sign failed");
                std::process::exit(2);
            };
            if public_key4.verify(&message[..length], &signature).is_err() {
                eprintln!("fuzz: random qhs4 verify failed");
                std::process::exit(2);
            }
        }
    }
    let qhs42_keys = if seconds >= 30 {
        let Ok((private_key42, public_key42)) = qhs42_keygen(&seed) else {
            eprintln!("fuzz: qhs42 keygen failed");
            std::process::exit(2);
        };
        let Ok(valid_signature42) = qhs42_sign_parallel(&private_key42, b"fuzz-seed-qhs42") else {
            eprintln!("fuzz: qhs42 seed sign failed");
            std::process::exit(2);
        };
        if public_key42
            .verify(b"fuzz-seed-qhs42", &valid_signature42)
            .is_err()
        {
            eprintln!("fuzz: qhs42 seed verify failed");
            std::process::exit(2);
        }
        Some((private_key42, public_key42, valid_signature42))
    } else {
        None
    };
    let fallback_public42 = Qhs42PublicKey::from_root([0_u8; 32], [0_u8; 32]);
    let fallback_signature42 = Qhs42Signature::from_bytes([0_u8; QHS42_SIGNATURE_BYTES]);
    let (public_key42, valid_signature42) = qhs42_keys
        .as_ref()
        .map_or((&fallback_public42, &fallback_signature42), |keys| {
            (&keys.1, &keys.2)
        });
    if let Some((private_key42, _, _)) = &qhs42_keys
        && seconds >= 60
    {
        for _ in 0..2 {
            let length = usize::try_from(rng.next() % 257).unwrap_or(0);
            let mut message = [0_u8; 256];
            rng.fill(&mut message[..length]);
            let Ok(signature) = qhs42_sign_parallel(private_key42, &message[..length]) else {
                eprintln!("fuzz: random qhs42 sign failed");
                std::process::exit(2);
            };
            if public_key42.verify(&message[..length], &signature).is_err() {
                eprintln!("fuzz: random qhs42 verify failed");
                std::process::exit(2);
            }
        }
    }
    let qhs5_keys = if seconds >= 30 {
        let seed5 = [7_u8; 64];
        let Ok((mut private_key5, public_key5)) = qhs5_keygen(&seed5) else {
            eprintln!("fuzz: qhs5 keygen failed");
            std::process::exit(2);
        };
        let Ok(valid_signature5) = private_key5.sign(b"fuzz-seed-qhs5") else {
            eprintln!("fuzz: qhs5 seed sign failed");
            std::process::exit(2);
        };
        if public_key5
            .verify(b"fuzz-seed-qhs5", &valid_signature5)
            .is_err()
        {
            eprintln!("fuzz: qhs5 seed verify failed");
            std::process::exit(2);
        }
        Some((private_key5, public_key5, valid_signature5))
    } else {
        None
    };
    let fallback_public5 = Qhs5PublicKey::from_root([0_u8; 64]);
    let fallback_signature5 = Qhs5Signature::from_bytes([0_u8; QHS5_SIGNATURE_BYTES]);
    let (public_key5, valid_signature5) = qhs5_keys
        .as_ref()
        .map_or((&fallback_public5, &fallback_signature5), |keys| {
            (&keys.1, &keys.2)
        });
    if let Some((private_key5, _, _)) = &qhs5_keys
        && seconds >= 60
    {
        let mut private_key5 = match Qhs5PrivateKey::from_bytes(&private_key5.to_bytes()) {
            Ok(key) => key,
            Err(_) => {
                eprintln!("fuzz: qhs5 key reparse failed");
                std::process::exit(2);
            }
        };
        for _ in 0..2 {
            let length = usize::try_from(rng.next() % 257).unwrap_or(0);
            let mut message = [0_u8; 256];
            rng.fill(&mut message[..length]);
            let Ok(signature) = private_key5.sign(&message[..length]) else {
                eprintln!("fuzz: random qhs5 sign failed");
                std::process::exit(2);
            };
            if public_key5.verify(&message[..length], &signature).is_err() {
                eprintln!("fuzz: random qhs5 verify failed");
                std::process::exit(2);
            }
        }
    }
    let qhs6_keys = if seconds >= 30 {
        let qhs5_seed = [7_u8; 64];
        let ed25519_seed = [9_u8; 32];
        let Ok((mut private_key6, public_key6)) = qhs6_keygen(&qhs5_seed, &ed25519_seed) else {
            eprintln!("fuzz: qhs6 keygen failed");
            std::process::exit(2);
        };
        let Ok(valid_signature6) = private_key6.sign(b"fuzz-seed-qhs6") else {
            eprintln!("fuzz: qhs6 seed sign failed");
            std::process::exit(2);
        };
        if public_key6
            .verify(b"fuzz-seed-qhs6", &valid_signature6)
            .is_err()
        {
            eprintln!("fuzz: qhs6 seed verify failed");
            std::process::exit(2);
        }
        Some((private_key6, public_key6, valid_signature6))
    } else {
        None
    };
    let fallback_public6 = Qhs6PublicKey::from_parts(
        Qhs5PublicKey::from_root([0_u8; 64]),
        Ed25519PrivateKey::from_seed([0_u8; 32]).public_key(),
    );
    let fallback_signature6 = match Qhs6Signature::from_parts(
        0,
        fallback_qhs5_signature(),
        Ed25519Signature::from_bytes([0_u8; 64]),
    ) {
        Ok(signature) => signature,
        Err(_) => {
            eprintln!("fuzz: qhs6 fallback signature failed");
            std::process::exit(2);
        }
    };
    let (public_key6, valid_signature6) = qhs6_keys
        .as_ref()
        .map_or((&fallback_public6, &fallback_signature6), |keys| {
            (&keys.1, &keys.2)
        });
    if let Some((private_key6, _, _)) = &qhs6_keys
        && seconds >= 60
    {
        let mut private_key6 = match Qhs6PrivateKey::from_bytes(&private_key6.to_bytes()) {
            Ok(key) => key,
            Err(_) => {
                eprintln!("fuzz: qhs6 key reparse failed");
                std::process::exit(2);
            }
        };
        for _ in 0..2 {
            let length = usize::try_from(rng.next() % 257).unwrap_or(0);
            let mut message = [0_u8; 256];
            rng.fill(&mut message[..length]);
            let Ok(signature) = private_key6.sign(&message[..length]) else {
                eprintln!("fuzz: random qhs6 sign failed");
                std::process::exit(2);
            };
            if public_key6.verify(&message[..length], &signature).is_err() {
                eprintln!("fuzz: random qhs6 verify failed");
                std::process::exit(2);
            }
        }
    }
    random_rounds(&mut rng);

    let mut iterations: u64 = 0;
    let mut panics: u64 = 0;
    let mut last_progress = Instant::now();
    while Instant::now() < deadline {
        iterations = iterations.saturating_add(1);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut braid_bytes = [0_u8; BRAID_BYTES];
            rng.fill(&mut braid_bytes);
            if let Ok(braid) = Braid::from_bytes(&braid_bytes) {
                let _ = braid.to_bytes();
                let _ = braid.validate();
            }

            let mut polynomial_bytes = [0_u8; PUBLIC_KEY_BYTES];
            rng.fill(&mut polynomial_bytes);
            let polynomial = Polynomial::from_bytes(&polynomial_bytes);
            let _ = polynomial.to_bytes();

            let mut public_bytes = [0_u8; QHS_PUBLIC_KEY_BYTES];
            rng.fill(&mut public_bytes);
            let _ = QhsPublicKey::from_bytes(&public_bytes);

            let mut private_bytes = [0_u8; QHS_PRIVATE_KEY_BYTES];
            rng.fill(&mut private_bytes);
            let _ = QhsPrivateKey::from_bytes(&private_bytes);

            let mut signature_bytes = [0_u8; QHS_SIGNATURE_BYTES];
            rng.fill(&mut signature_bytes);
            let signature = QhsSignature::from_bytes(signature_bytes);
            let _ = signature.leaf_index();

            let mut public_bytes2 = [0_u8; QHS2_PUBLIC_KEY_BYTES];
            rng.fill(&mut public_bytes2);
            let _ = Qhs2PublicKey::from_bytes(&public_bytes2);

            let mut private_bytes2 = [0_u8; QHS2_PRIVATE_KEY_BYTES];
            rng.fill(&mut private_bytes2);
            let _ = Qhs2PrivateKey::from_bytes(&private_bytes2);

            let mut signature_bytes2 = [0_u8; QHS2_SIGNATURE_BYTES];
            rng.fill(&mut signature_bytes2);
            let signature2 = Qhs2Signature::from_bytes(signature_bytes2);
            let _ = signature2.leaf_index();

            let mut public_bytes3 = [0_u8; QHS3_PUBLIC_KEY_BYTES];
            rng.fill(&mut public_bytes3);
            let _ = Qhs3PublicKey::from_bytes(&public_bytes3);

            let mut private_bytes3 = [0_u8; QHS3_PRIVATE_KEY_BYTES];
            rng.fill(&mut private_bytes3);
            let _ = Qhs3PrivateKey::from_bytes(&private_bytes3);

            let mut signature_bytes3 = [0_u8; QHS3_SIGNATURE_BYTES];
            rng.fill(&mut signature_bytes3);
            let signature3 = Qhs3Signature::from_bytes(signature_bytes3);
            let _ = signature3.leaf_index();

            let mut public_bytes4 = [0_u8; QHS4_PUBLIC_KEY_BYTES];
            rng.fill(&mut public_bytes4);
            let _ = Qhs4PublicKey::from_bytes(&public_bytes4);

            let mut private_bytes4 = [0_u8; QHS4_PRIVATE_KEY_BYTES];
            rng.fill(&mut private_bytes4);
            let _ = Qhs4PrivateKey::from_bytes(&private_bytes4);

            let mut signature_bytes4 = [0_u8; QHS4_SIGNATURE_BYTES];
            rng.fill(&mut signature_bytes4);
            let signature4 = Qhs4Signature::from_bytes(signature_bytes4);
            let short_length = usize::try_from(rng.next() % 18_217).unwrap_or(0);
            let _ = Qhs4Signature::from_slice(&signature4.as_bytes()[..short_length]);

            let mut public_bytes42 = [0_u8; QHS42_PUBLIC_KEY_BYTES];
            rng.fill(&mut public_bytes42);
            let _ = Qhs42PublicKey::from_bytes(&public_bytes42);

            let mut private_bytes42 = [0_u8; QHS42_PRIVATE_KEY_BYTES];
            rng.fill(&mut private_bytes42);
            let _ = Qhs42PrivateKey::from_bytes(&private_bytes42);

            let mut signature_bytes42 = [0_u8; QHS42_SIGNATURE_BYTES];
            rng.fill(&mut signature_bytes42);
            let signature42 = Qhs42Signature::from_bytes(signature_bytes42);
            let signature_limit =
                u64::try_from(QHS42_SIGNATURE_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
            let short_length42 = usize::try_from(rng.next() % signature_limit).unwrap_or(0);
            let _ = Qhs42Signature::from_slice(&signature42.as_bytes()[..short_length42]);

            let mut public_bytes5 = [0_u8; QHS5_PUBLIC_KEY_BYTES];
            rng.fill(&mut public_bytes5);
            let _ = Qhs5PublicKey::from_bytes(&public_bytes5);

            let mut private_bytes5 = [0_u8; QHS5_PRIVATE_KEY_BYTES];
            rng.fill(&mut private_bytes5);
            let _ = Qhs5PrivateKey::from_bytes(&private_bytes5);

            let mut signature_bytes5 = [0_u8; QHS5_SIGNATURE_BYTES];
            rng.fill(&mut signature_bytes5);
            let signature5 = Qhs5Signature::from_bytes(signature_bytes5);
            let signature_limit5 =
                u64::try_from(QHS5_SIGNATURE_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
            let short_length5 = usize::try_from(rng.next() % signature_limit5).unwrap_or(0);
            let _ = Qhs5Signature::from_slice(&signature5.as_bytes()[..short_length5]);

            let mut public_bytes6 = [0_u8; QHS6_PUBLIC_KEY_BYTES];
            rng.fill(&mut public_bytes6);
            let _ = Qhs6PublicKey::from_bytes(&public_bytes6);

            let mut private_bytes6 = [0_u8; QHS6_PRIVATE_KEY_BYTES];
            rng.fill(&mut private_bytes6);
            let _ = Qhs6PrivateKey::from_bytes(&private_bytes6);

            let mut signature_bytes6 = [0_u8; QHS6_SIGNATURE_BYTES];
            rng.fill(&mut signature_bytes6);
            let signature6 = match Qhs6Signature::from_slice(&signature_bytes6) {
                Ok(signature) => signature,
                Err(_) => match Qhs6Signature::from_parts(
                    0,
                    fallback_qhs5_signature(),
                    Ed25519Signature::from_bytes([0_u8; 64]),
                ) {
                    Ok(signature) => signature,
                    Err(_) => fallback_signature6,
                },
            };
            let signature_limit6 =
                u64::try_from(QHS6_SIGNATURE_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
            let short_length6 = usize::try_from(rng.next() % signature_limit6).unwrap_or(0);
            let _ = Qhs6Signature::from_slice(&signature6.as_bytes()[..short_length6]);

            let length = usize::try_from(rng.next() % 257).unwrap_or(0);
            let mut message = [0_u8; 256];
            rng.fill(&mut message[..length]);
            let message = &message[..length];
            let _ = public_key.verify(message, &signature);
            let _ = public_key2.verify(message, &signature2);
            let _ = public_key3.verify(message, &signature3);
            let _ = public_key4.verify(message, &signature4);
            let _ = public_key42.verify(message, &signature42);
            let _ = public_key5.verify(message, &signature5);
            let _ = public_key6.verify(message, &signature6);

            let mut qhse_sig1 = [0_u8; 2_408];
            rng.fill(&mut qhse_sig1);
            let _ = verify_qhs1(&public_key.to_bytes(), message, &qhse_sig1);
            let mut qhse_sig2 = [0_u8; 1_704];
            rng.fill(&mut qhse_sig2);
            let _ = verify_qhs2(&public_key2.to_bytes(), message, &qhse_sig2);
            let mut qhse_sig3 = [0_u8; 1_832];
            rng.fill(&mut qhse_sig3);
            let _ = verify_qhs3(&public_key3.to_bytes(), message, &qhse_sig3);
            let _ = verify_qhs31(&public_key3.to_bytes(), message, &qhse_sig3);
            if iterations.is_multiple_of(1_000) {
                let _ = public_key4.verify(b"fuzz-seed-qhs4", valid_signature4);
                let _ = public_key42.verify(b"fuzz-seed-qhs42", valid_signature42);
                let _ = public_key5.verify(b"fuzz-seed-qhs5", valid_signature5);
                let _ = public_key6.verify(b"fuzz-seed-qhs6", valid_signature6);
                let _ = verify_qhs1(
                    &public_key.to_bytes(),
                    b"fuzz-seed",
                    &valid_signature.to_bytes(),
                );
                let _ = verify_qhs2(
                    &public_key2.to_bytes(),
                    b"fuzz-seed-qhs2",
                    &valid_signature2.to_bytes(),
                );
                let _ = verify_qhs3(
                    &public_key3.to_bytes(),
                    b"fuzz-seed-qhs3",
                    &valid_signature3.to_bytes(),
                );
                let _ = verify_qhs31(
                    &public_key3.to_bytes(),
                    b"fuzz-seed-qhs3",
                    &valid_signature3.to_bytes(),
                );
            }
        }));
        if result.is_err() {
            panics = panics.saturating_add(1);
            eprintln!("fuzz: panic at iteration {iterations}");
            break;
        }
        if iterations.is_multiple_of(100_000) && last_progress.elapsed() >= Duration::from_secs(60)
        {
            println!(
                "fuzz: progress seconds={} iterations={iterations} panics={panics}",
                started.elapsed().as_secs()
            );
            last_progress = Instant::now();
        }
    }

    println!(
        "fuzz: seconds={seconds} iterations={iterations} panics={panics} seed=0x{rng_seed:016x}"
    );
    if panics == 0 {
        std::process::exit(0);
    }
    std::process::exit(1);
}
