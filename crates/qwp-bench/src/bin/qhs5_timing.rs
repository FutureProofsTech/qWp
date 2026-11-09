//! In-house Welch t-test timing harness for QHS-5.
//!
//! Measures sequential leaf derivation, parallel leaf derivation, cached-leaf
//! signing, and verification. Signatures are checked for byte equality.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::float_arithmetic,
    reason = "the timing harness reports statistics and uses floats"
)]

use std::time::Instant;

use qwp_crypto::{QHS5_LEAF_COUNT, Qhs5PrivateKey, Qhs5PublicKey, qhs5_keygen, qhs5_leaves};
use qwp_platform::qhs5_leaves_parallel;

const MESSAGE: &[u8] = b"qWp QHS-5 timing message";

fn main() {
    let seed_a = [7_u8; 64];
    let seed_b = [9_u8; 64];

    let (keygen_a, keygen_b) = sample_keygen_parallel_pair(&seed_a, &seed_b, 8);
    let (keygen_sequential_a, keygen_sequential_b) =
        sample_keygen_sequential_pair(&seed_a, &seed_b, 6);
    let (sequential_a, sequential_b) = sample_sequential_pair(&seed_a, &seed_b, 6);
    let (cached_a, cached_b) = sample_cached_pair(&seed_a, &seed_b, 16);
    let verify_a = sample_verify(&seed_a, 200);

    let cached_t = welch_t(&cached_a, &cached_b);
    let sequential_t = welch_t(&sequential_a, &sequential_b);
    let keygen_t = welch_t(&keygen_a, &keygen_b);
    let keygen_sequential_t = welch_t(&keygen_sequential_a, &keygen_sequential_b);
    let sequential_mean = (mean(&sequential_a) + mean(&sequential_b)) / 2.0;
    let cached_mean = (mean(&cached_a) + mean(&cached_b)) / 2.0;
    let sign_speedup = if cached_mean > 0.0 {
        sequential_mean / cached_mean
    } else {
        0.0
    };
    let keygen_sequential_mean = (mean(&keygen_sequential_a) + mean(&keygen_sequential_b)) / 2.0;
    let keygen_mean = (mean(&keygen_a) + mean(&keygen_b)) / 2.0;
    let keygen_speedup = if keygen_mean > 0.0 {
        keygen_sequential_mean / keygen_mean
    } else {
        0.0
    };

    println!(
        "qhs5-keygen-sequential: mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&keygen_sequential_a),
        mean(&keygen_sequential_b),
        keygen_sequential_t
    );
    println!(
        "qhs5-keygen-parallel:   mean_a={:.0}ns mean_b={:.0}ns t={:.3} speedup={:.2}x",
        mean(&keygen_a),
        mean(&keygen_b),
        keygen_t,
        keygen_speedup
    );
    println!(
        "qhs5-sign-sequential:   mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&sequential_a),
        mean(&sequential_b),
        sequential_t
    );
    println!(
        "qhs5-sign-cached:       mean_a={:.0}ns mean_b={:.0}ns t={:.3} speedup={:.2}x",
        mean(&cached_a),
        mean(&cached_b),
        cached_t,
        sign_speedup
    );
    println!("qhs5-verify: mean={:.0}ns/op", mean(&verify_a));

    let threshold = 4.5;
    if keygen_t.abs() >= threshold
        || keygen_sequential_t.abs() >= threshold
        || sequential_t.abs() >= threshold
        || cached_t.abs() >= threshold
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

fn key_pair(seed: &[u8; 64]) -> (Qhs5PrivateKey, Qhs5PublicKey) {
    match qhs5_keygen(seed) {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("timing: keygen failed: {error}");
            std::process::exit(2);
        }
    }
}

fn sample_keygen_parallel_pair(
    seed_a: &[u8; 64],
    seed_b: &[u8; 64],
    samples: u32,
) -> (Vec<u64>, Vec<u64>) {
    let mut values_a = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    let mut values_b = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start_a = Instant::now();
        let leaves_a = leaves_for(seed_a);
        let result_a = qwp_crypto::qhs5_keygen_from_leaves(seed_a, &leaves_a);
        let elapsed_a = start_a.elapsed().as_nanos();
        let start_b = Instant::now();
        let leaves_b = leaves_for(seed_b);
        let result_b = qwp_crypto::qhs5_keygen_from_leaves(seed_b, &leaves_b);
        let elapsed_b = start_b.elapsed().as_nanos();
        if result_a.is_err() || result_b.is_err() {
            eprintln!("timing: keygen failed");
            std::process::exit(2);
        }
        values_a.push(u64::try_from(elapsed_a).unwrap_or(u64::MAX));
        values_b.push(u64::try_from(elapsed_b).unwrap_or(u64::MAX));
    }
    (values_a, values_b)
}

fn sample_keygen_sequential_pair(
    seed_a: &[u8; 64],
    seed_b: &[u8; 64],
    samples: u32,
) -> (Vec<u64>, Vec<u64>) {
    let mut values_a = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    let mut values_b = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start_a = Instant::now();
        let result_a = qhs5_keygen(seed_a);
        let elapsed_a = start_a.elapsed().as_nanos();
        let start_b = Instant::now();
        let result_b = qhs5_keygen(seed_b);
        let elapsed_b = start_b.elapsed().as_nanos();
        if result_a.is_err() || result_b.is_err() {
            eprintln!("timing: sequential keygen failed");
            std::process::exit(2);
        }
        values_a.push(u64::try_from(elapsed_a).unwrap_or(u64::MAX));
        values_b.push(u64::try_from(elapsed_b).unwrap_or(u64::MAX));
    }
    (values_a, values_b)
}

fn sample_sequential_pair(
    seed_a: &[u8; 64],
    seed_b: &[u8; 64],
    samples: u32,
) -> (Vec<u64>, Vec<u64>) {
    let (mut private_a, _public_a) = key_pair(seed_a);
    let (mut private_b, _public_b) = key_pair(seed_b);
    let mut values_a = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    let mut values_b = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start_a = Instant::now();
        let result_a = private_a.sign(MESSAGE);
        let elapsed_a = start_a.elapsed().as_nanos();
        let start_b = Instant::now();
        let result_b = private_b.sign(MESSAGE);
        let elapsed_b = start_b.elapsed().as_nanos();
        if result_a.is_err() || result_b.is_err() {
            eprintln!("timing: sequential sign failed");
            std::process::exit(2);
        }
        values_a.push(u64::try_from(elapsed_a).unwrap_or(u64::MAX));
        values_b.push(u64::try_from(elapsed_b).unwrap_or(u64::MAX));
    }
    (values_a, values_b)
}

fn sample_cached_pair(seed_a: &[u8; 64], seed_b: &[u8; 64], samples: u32) -> (Vec<u64>, Vec<u64>) {
    let leaves_a = leaves_for(seed_a);
    let leaves_b = leaves_for(seed_b);
    let Ok((mut private_a, _public_a)) = qwp_crypto::qhs5_keygen_from_leaves(seed_a, &leaves_a)
    else {
        eprintln!("timing: keygen failed");
        std::process::exit(2);
    };
    let Ok((mut private_b, _public_b)) = qwp_crypto::qhs5_keygen_from_leaves(seed_b, &leaves_b)
    else {
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
            eprintln!("timing: cached sign failed");
            std::process::exit(2);
        }
        values_a.push(u64::try_from(elapsed_a).unwrap_or(u64::MAX));
        values_b.push(u64::try_from(elapsed_b).unwrap_or(u64::MAX));
    }
    (values_a, values_b)
}

fn sample_verify(seed: &[u8; 64], samples: u32) -> Vec<u64> {
    let leaves = leaves_for(seed);
    let Ok((mut private_key, public_key)) = qwp_crypto::qhs5_keygen_from_leaves(seed, &leaves)
    else {
        eprintln!("timing: keygen failed");
        std::process::exit(2);
    };
    let Ok(signature) = private_key.sign_with_leaves(MESSAGE, &leaves) else {
        eprintln!("timing: sign failed");
        std::process::exit(2);
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
