//! In-house Welch t-test timing harness for QHS-3.1.
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

use qwp_crypto::{
    QHS3_LEAF_COUNT, QHS3_TREE_NODES, qhs3_auth_path_from_tree, qhs3_build_tree,
    qhs3_keygen_from_leaves, qhs3_leaf,
};
use qwp_platform::qhs3_leaves_parallel;

fn main() {
    let seed_a = [7_u8; 32];
    let seed_b = [9_u8; 32];
    let samples = 12_u32;

    let keygen_a = sample_keygen(&seed_a, samples);
    let keygen_b = sample_keygen(&seed_b, samples);
    let sign_a = sample_sign(&seed_a, samples);
    let sign_b = sample_sign(&seed_b, samples);
    let verify_a = sample_verify(&seed_a, 1000);

    let keygen_t = welch_t(&keygen_a, &keygen_b);
    let sign_t = welch_t(&sign_a, &sign_b);
    println!(
        "qhs31-keygen: mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&keygen_a),
        mean(&keygen_b),
        keygen_t
    );
    println!(
        "qhs31-sign:   mean_a={:.0}ns mean_b={:.0}ns t={:.3}",
        mean(&sign_a),
        mean(&sign_b),
        sign_t
    );
    println!("qhs31-verify: mean={:.0}ns/op", mean(&verify_a));

    let threshold = 4.5;
    if keygen_t.abs() >= threshold || sign_t.abs() >= threshold {
        eprintln!("timing: t-stat above {threshold}; investigate leakage");
        std::process::exit(1);
    }
    println!("timing: ok (threshold |t| < {threshold})");
}

fn leaves_for(seed: &[u8; 32]) -> Vec<[u8; 32]> {
    match qhs3_leaves_parallel(seed) {
        Ok(leaves) => leaves,
        Err(_) => {
            let mut leaves = Vec::with_capacity(QHS3_LEAF_COUNT);
            for index in 0..QHS3_LEAF_COUNT {
                let leaf_index = match u16::try_from(index) {
                    Ok(value) => value,
                    Err(_) => {
                        eprintln!("timing: leaf index");
                        std::process::exit(2);
                    }
                };
                match qhs3_leaf(seed, leaf_index) {
                    Ok(leaf) => leaves.push(leaf),
                    Err(error) => {
                        eprintln!("timing: leaves failed: {error}");
                        std::process::exit(2);
                    }
                }
            }
            leaves
        }
    }
}

fn tree_for(seed: &[u8; 32]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let leaves = leaves_for(seed);
    let mut nodes = vec![[0_u8; 32]; QHS3_TREE_NODES];
    if qhs3_build_tree(&leaves, &mut nodes).is_err() {
        eprintln!("timing: tree build failed");
        std::process::exit(2);
    }
    (leaves, nodes)
}

fn sample_keygen(seed: &[u8; 32], samples: u32) -> Vec<u64> {
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let (leaves, _nodes) = tree_for(seed);
        let result = qhs3_keygen_from_leaves(seed, &leaves);
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
    let (leaves, nodes) = tree_for(seed);
    let Ok((mut private_key, _public_key)) = qhs3_keygen_from_leaves(seed, &leaves) else {
        eprintln!("timing: keygen failed");
        std::process::exit(2);
    };
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let auth_path = match qhs3_auth_path_from_tree(&leaves, &nodes, private_key.next_leaf()) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("timing: auth path failed: {error}");
                std::process::exit(2);
            }
        };
        let result = private_key.sign_with_auth_path(b"qWp QHS-3.1 timing message", &auth_path);
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
    let (leaves, nodes) = tree_for(seed);
    let Ok((mut private_key, public_key)) = qhs3_keygen_from_leaves(seed, &leaves) else {
        eprintln!("timing: keygen failed");
        std::process::exit(2);
    };
    let Ok(auth_path) = qhs3_auth_path_from_tree(&leaves, &nodes, 0) else {
        eprintln!("timing: auth path failed");
        std::process::exit(2);
    };
    let Ok(signature) = private_key.sign_with_auth_path(b"qWp QHS-3.1 verify timing", &auth_path)
    else {
        eprintln!("timing: sign failed");
        std::process::exit(2);
    };
    let mut values = Vec::with_capacity(usize::try_from(samples).unwrap_or(0));
    for _ in 0..samples {
        let start = Instant::now();
        let result = public_key.verify(b"qWp QHS-3.1 verify timing", &signature);
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
