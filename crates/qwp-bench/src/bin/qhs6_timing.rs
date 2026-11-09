//! In-house Welch t-test timing harness for QHS-6 and Ed25519.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::float_arithmetic,
    reason = "the timing harness reports statistics and uses floats"
)]

use std::time::Instant;

use qwp_classical::Ed25519PrivateKey;
use qwp_crypto::{QHS5_LEAF_COUNT, qhs5_leaves, qhs6_keygen_from_leaves};
use qwp_platform::qhs5_leaves_parallel;

const MESSAGE: &[u8] = b"qWp QHS-6 timing message";

fn main() {
    let qhs5_a = [7_u8; 64];
    let qhs5_b = [9_u8; 64];
    let ed_a = [7_u8; 32];
    let ed_b = [9_u8; 32];

    let keygen_a = sample_keygen(&qhs5_a, &ed_a, 8);
    let keygen_b = sample_keygen(&qhs5_b, &ed_b, 8);
    let (sign_a, sign_b) = sample_sign_pair(&qhs5_a, &qhs5_b, &ed_a, &ed_b, 16);
    let verify_a = sample_verify(&qhs5_a, &ed_a, 200);

    let ed_keygen_a = sample_ed_keygen(&ed_a, 100);
    let ed_keygen_b = sample_ed_keygen(&ed_b, 100);
    let (ed_sign_a, ed_sign_b) = sample_ed_sign_pair(&ed_a, &ed_b, 1000);
    let ed_verify_a = sample_ed_verify(&ed_a, 500);

    let keygen_t = welch_t(&keygen_a, &keygen_b);
    let sign_t = welch_t(&sign_a, &sign_b);
    let ed_keygen_t = welch_t(&ed_keygen_a, &ed_keygen_b);
    let ed_sign_t = welch_t(&ed_sign_a, &ed_sign_b);

    println!(
        "qhs6-keygen-parallel: mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&keygen_a),
        mean(&keygen_b),
        keygen_t
    );
    println!(
        "qhs6-sign-cached:     mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&sign_a),
        mean(&sign_b),
        sign_t
    );
    println!("qhs6-verify: mean={:.0}ns/op", mean(&verify_a));
    println!(
        "ed25519-keygen: mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&ed_keygen_a),
        mean(&ed_keygen_b),
        ed_keygen_t
    );
    println!(
        "ed25519-sign:   mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&ed_sign_a),
        mean(&ed_sign_b),
        ed_sign_t
    );
    println!("ed25519-verify: mean={:.0}ns/op", mean(&ed_verify_a));

    let threshold = 4.5;
    if keygen_t.abs() >= threshold
        || sign_t.abs() >= threshold
        || ed_keygen_t.abs() >= threshold
        || ed_sign_t.abs() >= threshold
    {
        eprintln!("timing: t-stat above {threshold}; investigate leakage");
        std::process::exit(1);
    }
    println!("timing: ok (threshold |t| < {threshold})");
}

fn leaves_for(seed: &[u8; 64]) -> [[u8; 64]; QHS5_LEAF_COUNT] {
    match qhs5_leaves_parallel(seed) {
        Ok(leaves) => leaves,
        Err(_) => match qhs5_leaves(seed) {
            Ok(leaves) => leaves,
            Err(error) => {
                eprintln!("timing: leaves failed: {error}");
                std::process::exit(2);
            }
        },
    }
}

fn sample_keygen(qhs5_seed: &[u8; 64], ed_seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let leaves = leaves_for(qhs5_seed);
        let result = qhs6_keygen_from_leaves(qhs5_seed, ed_seed, &leaves);
        let elapsed = start.elapsed().as_nanos();
        if result.is_err() {
            eprintln!("timing: keygen failed");
            std::process::exit(2);
        }
        values.push(u64::try_from(elapsed).unwrap_or(u64::MAX));
    }
    values
}

fn sample_sign_pair(
    qhs5_a: &[u8; 64],
    qhs5_b: &[u8; 64],
    ed_a: &[u8; 32],
    ed_b: &[u8; 32],
    samples: u32,
) -> (Vec<u64>, Vec<u64>) {
    let leaves_a = leaves_for(qhs5_a);
    let leaves_b = leaves_for(qhs5_b);
    let Ok((mut private_a, _public_a)) = qhs6_keygen_from_leaves(qhs5_a, ed_a, &leaves_a) else {
        eprintln!("timing: keygen failed");
        std::process::exit(2);
    };
    let Ok((mut private_b, _public_b)) = qhs6_keygen_from_leaves(qhs5_b, ed_b, &leaves_b) else {
        eprintln!("timing: keygen failed");
        std::process::exit(2);
    };
    let mut values_a = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    let mut values_b = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start_a = Instant::now();
        let result_a = private_a.sign_with_leaves(MESSAGE, &leaves_a);
        let elapsed_a = start_a.elapsed().as_nanos();
        let start_b = Instant::now();
        let result_b = private_b.sign_with_leaves(MESSAGE, &leaves_b);
        let elapsed_b = start_b.elapsed().as_nanos();
        if result_a.is_err() || result_b.is_err() {
            eprintln!("timing: sign failed");
            std::process::exit(2);
        }
        values_a.push(u64::try_from(elapsed_a).unwrap_or(u64::MAX));
        values_b.push(u64::try_from(elapsed_b).unwrap_or(u64::MAX));
    }
    (values_a, values_b)
}

fn sample_verify(qhs5_seed: &[u8; 64], ed_seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let leaves = leaves_for(qhs5_seed);
    let Ok((mut private, public)) = qhs6_keygen_from_leaves(qhs5_seed, ed_seed, &leaves) else {
        eprintln!("timing: keygen failed");
        std::process::exit(2);
    };
    let Ok(signature) = private.sign_with_leaves(MESSAGE, &leaves) else {
        eprintln!("timing: sign failed");
        std::process::exit(2);
    };
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let result = public.verify(MESSAGE, &signature);
        let elapsed = start.elapsed().as_nanos();
        if result.is_err() {
            eprintln!("timing: verify failed");
            std::process::exit(2);
        }
        values.push(u64::try_from(elapsed).unwrap_or(u64::MAX));
    }
    values
}

fn sample_ed_keygen(seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let private = Ed25519PrivateKey::from_seed(*seed);
        let _ = private.public_key();
        let elapsed = start.elapsed().as_nanos();
        values.push(u64::try_from(elapsed).unwrap_or(u64::MAX));
    }
    values
}

fn sample_ed_sign_pair(seed_a: &[u8; 32], seed_b: &[u8; 32], samples: u32) -> (Vec<u64>, Vec<u64>) {
    let private_a = Ed25519PrivateKey::from_seed(*seed_a);
    let private_b = Ed25519PrivateKey::from_seed(*seed_b);
    let mut values_a = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    let mut values_b = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start_a = Instant::now();
        let _ = private_a.sign(MESSAGE);
        let elapsed_a = start_a.elapsed().as_nanos();
        let start_b = Instant::now();
        let _ = private_b.sign(MESSAGE);
        let elapsed_b = start_b.elapsed().as_nanos();
        values_a.push(u64::try_from(elapsed_a).unwrap_or(u64::MAX));
        values_b.push(u64::try_from(elapsed_b).unwrap_or(u64::MAX));
    }
    (values_a, values_b)
}

fn sample_ed_verify(seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let private = Ed25519PrivateKey::from_seed(*seed);
    let public = private.public_key();
    let signature = private.sign(MESSAGE);
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let result = public.verify(MESSAGE, &signature);
        let elapsed = start.elapsed().as_nanos();
        if result.is_err() {
            eprintln!("timing: ed25519 verify failed");
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
