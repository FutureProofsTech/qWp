//! Host timing harness for the QHS-E verifier profile.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::float_arithmetic,
    reason = "the timing harness reports statistics and uses floats"
)]

use std::time::Instant;

use qwp_crypto::{
    Qhs2Signature, Qhs3Signature, QhsSignature, qhs_keygen, qhs2_keygen, qhs3_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};

const SEED: [u8; 32] = [7_u8; 32];
const MESSAGE: &[u8] = b"qWp QHS-E timing message";

fn main() {
    let (mut private1, public1) = qhs_keygen(&SEED).unwrap_or_else(|error| {
        eprintln!("qhse-timing: qhs1 keygen failed: {error}");
        std::process::exit(2);
    });
    let signature1 = private1.sign(MESSAGE).unwrap_or_else(|error| {
        eprintln!("qhse-timing: qhs1 sign failed: {error}");
        std::process::exit(2);
    });
    let (mut private2, public2) = qhs2_keygen(&SEED).unwrap_or_else(|error| {
        eprintln!("qhse-timing: qhs2 keygen failed: {error}");
        std::process::exit(2);
    });
    let signature2 = private2.sign(MESSAGE).unwrap_or_else(|error| {
        eprintln!("qhse-timing: qhs2 sign failed: {error}");
        std::process::exit(2);
    });
    let (mut private3, public3) = qhs3_keygen(&SEED).unwrap_or_else(|error| {
        eprintln!("qhse-timing: qhs3 keygen failed: {error}");
        std::process::exit(2);
    });
    let signature3 = private3.sign(MESSAGE).unwrap_or_else(|error| {
        eprintln!("qhse-timing: qhs3 sign failed: {error}");
        std::process::exit(2);
    });

    let public1 = public1.to_bytes();
    let public2 = public2.to_bytes();
    let public3 = public3.to_bytes();
    let signature1 = signature1.to_bytes();
    let signature2 = signature2.to_bytes();
    let signature3 = signature3.to_bytes();

    let qhs1 = sample(10_000, || verify_qhs1(&public1, MESSAGE, &signature1));
    let qhs2 = sample(10_000, || verify_qhs2(&public2, MESSAGE, &signature2));
    let qhs3 = sample(5_000, || verify_qhs3(&public3, MESSAGE, &signature3));
    let qhs31 = sample(5_000, || verify_qhs31(&public3, MESSAGE, &signature3));

    println!("qhse-qhs1: mean={:.0}ns/op", mean(&qhs1));
    println!("qhse-qhs2: mean={:.0}ns/op", mean(&qhs2));
    println!("qhse-qhs3: mean={:.0}ns/op", mean(&qhs3));
    println!("qhse-qhs31: mean={:.0}ns/op", mean(&qhs31));

    let zero_rejected = verify_qhs1(&public1, MESSAGE, &[0_u8; 2_408]).is_err()
        && verify_qhs2(&public2, MESSAGE, &[0_u8; 1_704]).is_err()
        && verify_qhs3(&public3, MESSAGE, &[0_u8; 1_832]).is_err();
    if !zero_rejected {
        eprintln!("qhse-timing: zero signature accepted");
        std::process::exit(1);
    }
    let _ = QhsSignature::from_bytes(signature1);
    let _ = Qhs2Signature::from_bytes(signature2);
    let _ = Qhs3Signature::from_bytes(signature3);
    println!("timing: ok");
}

fn sample<F>(samples: u32, mut verify: F) -> Vec<u64>
where
    F: FnMut() -> Result<(), qwp_core::CryptoError>,
{
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let result = verify();
        let elapsed = start.elapsed().as_nanos();
        if result.is_err() {
            eprintln!("qhse-timing: verification failed");
            std::process::exit(2);
        }
        values.push(u64::try_from(elapsed).unwrap_or(u64::MAX));
    }
    values
}

fn mean(values: &[u64]) -> f64 {
    let sum: u128 = values.iter().map(|value| u128::from(*value)).sum();
    let count = u128::try_from(values.len()).unwrap_or(1);
    let mean = sum / count;
    f64::from(u32::try_from(mean).unwrap_or(u32::MAX))
}
