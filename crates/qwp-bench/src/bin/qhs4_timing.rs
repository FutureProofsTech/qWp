//! In-house Welch t-test timing harness for QHS-4.
//!
//! Measures keygen and sign across two secret seeds. A large t-stat is
//! evidence of secret-dependent timing; the harness exits non-zero.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::float_arithmetic,
    reason = "the timing harness reports statistics and uses floats"
)]

use std::time::Instant;

use qwp_crypto::{Qhs4PrivateKey, Qhs4PublicKey, qhs4_keygen};

const MESSAGE: &[u8] = b"qWp QHS-4 timing message";

fn main() {
    let seed_a = [7_u8; 32];
    let seed_b = [9_u8; 32];
    let samples = 8_u32;

    let keygen_a = sample_keygen(&seed_a, samples);
    let keygen_b = sample_keygen(&seed_b, samples);
    let sign_a = sample_sign(&seed_a, samples);
    let sign_b = sample_sign(&seed_b, samples);
    let verify_a = sample_verify(&seed_a, 200);

    let keygen_t = welch_t(&keygen_a, &keygen_b);
    let sign_t = welch_t(&sign_a, &sign_b);
    println!(
        "qhs4-keygen: mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&keygen_a),
        mean(&keygen_b),
        keygen_t
    );
    println!(
        "qhs4-sign:   mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&sign_a),
        mean(&sign_b),
        sign_t
    );
    println!("qhs4-verify: mean={:.0}ns/op", mean(&verify_a));

    let threshold = 4.5;
    if keygen_t.abs() >= threshold || sign_t.abs() >= threshold {
        eprintln!("timing: t-stat above {threshold}; investigate leakage");
        std::process::exit(1);
    }
    println!("timing: ok (threshold |t| < {threshold})");
}

fn key_pair(seed: &[u8; 32]) -> (Qhs4PrivateKey, Qhs4PublicKey) {
    match qhs4_keygen(seed) {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("timing: keygen failed: {error}");
            std::process::exit(2);
        }
    }
}

fn sample_keygen(seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let result = qhs4_keygen(seed);
        let elapsed = start.elapsed().as_nanos();
        if result.is_err() {
            eprintln!("timing: keygen failed");
            std::process::exit(2);
        }
        values.push(u64::try_from(elapsed).unwrap_or(u64::MAX));
    }
    values
}

fn sample_sign(seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let (private_key, _public_key) = key_pair(seed);
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let result = private_key.sign(MESSAGE);
        let elapsed = start.elapsed().as_nanos();
        if result.is_err() {
            eprintln!("timing: sign failed");
            std::process::exit(2);
        }
        values.push(u64::try_from(elapsed).unwrap_or(u64::MAX));
    }
    values
}

fn sample_verify(seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let (private_key, public_key) = key_pair(seed);
    let signature = match private_key.sign(MESSAGE) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("timing: sign failed: {error}");
            std::process::exit(2);
        }
    };
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let result = public_key.verify(MESSAGE, &signature);
        let elapsed = start.elapsed().as_nanos();
        if result.is_err() {
            eprintln!("timing: verify failed");
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

fn variance(values: &[u64], average: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let sum: f64 = values
        .iter()
        .map(|value| {
            let difference = f64::from(u32::try_from(*value).unwrap_or(u32::MAX)) - average;
            difference * difference
        })
        .sum();
    sum / f64::from(u32::try_from(values.len() - 1).unwrap_or(1))
}

fn welch_t(first: &[u64], second: &[u64]) -> f64 {
    let mean_first = mean(first);
    let mean_second = mean(second);
    let variance_first = variance(first, mean_first);
    let variance_second = variance(second, mean_second);
    let count_first = f64::from(u32::try_from(first.len()).unwrap_or(1));
    let count_second = f64::from(u32::try_from(second.len()).unwrap_or(1));
    let denominator = (variance_first / count_first + variance_second / count_second).sqrt();
    if denominator == 0.0 {
        if (mean_first - mean_second).abs() < f64::EPSILON {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        (mean_first - mean_second) / denominator
    }
}
