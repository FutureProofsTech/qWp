//! In-house qWp fuzz driver.
//!
//! No external fuzzing crate. Deterministic PRNG, fixed time budget, panic
//! detection, and parser/verifier round-trip checks.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use qwp_core::{BRAID_BYTES, Braid, PUBLIC_KEY_BYTES, Polynomial};
use qwp_crypto::{
    QHS_PRIVATE_KEY_BYTES, QHS_PUBLIC_KEY_BYTES, QHS_SIGNATURE_BYTES, QHS2_PRIVATE_KEY_BYTES,
    QHS2_PUBLIC_KEY_BYTES, QHS2_SIGNATURE_BYTES, QHS3_PRIVATE_KEY_BYTES, QHS3_PUBLIC_KEY_BYTES,
    QHS3_SIGNATURE_BYTES, Qhs2PrivateKey, Qhs2PublicKey, Qhs2Signature, Qhs3PrivateKey,
    Qhs3PublicKey, Qhs3Signature, QhsPrivateKey, QhsPublicKey, QhsSignature, qhs_keygen,
    qhs2_keygen, qhs3_keygen_from_leaves,
};
use qwp_platform::qhs3_leaves_parallel;

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

fn main() {
    let seconds = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut rng = Rng::new(0x9e37_79b9_7f4a_7c15);
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

    let mut iterations: u64 = 0;
    let mut panics: u64 = 0;
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

            let mut message = [0_u8; 64];
            rng.fill(&mut message);
            let _ = public_key.verify(&message, &signature);
            let _ = public_key2.verify(&message, &signature2);
            let _ = public_key3.verify(&message, &signature3);
        }));
        if result.is_err() {
            panics = panics.saturating_add(1);
            eprintln!("fuzz: panic at iteration {iterations}");
            break;
        }
    }

    println!("fuzz: seconds={seconds} iterations={iterations} panics={panics}");
    if panics == 0 {
        std::process::exit(0);
    }
    std::process::exit(1);
}
