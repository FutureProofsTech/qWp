//! In-house qWp fuzz driver.
//!
//! No external fuzzing crate. Deterministic PRNG, fixed time budget, panic
//! detection, and parser/verifier round-trip checks.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use qwp_core::{BRAID_BYTES, Braid, PUBLIC_KEY_BYTES, Polynomial};
use qwp_crypto::{
    QHS_PRIVATE_KEY_BYTES, QHS_PUBLIC_KEY_BYTES, QHS_SIGNATURE_BYTES, QhsPrivateKey, QhsPublicKey,
    QhsSignature, qhs_keygen,
};

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

            let mut message = [0_u8; 64];
            rng.fill(&mut message);
            let _ = public_key.verify(&message, &signature);
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
