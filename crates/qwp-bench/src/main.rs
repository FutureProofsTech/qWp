//! qWp in-house benchmark harness.

#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    reason = "the benchmark harness reports timings and performs fixed-count arithmetic"
)]

use std::hint::black_box;
use std::time::Instant;

use qwp_core::{Braid, Polynomial};
use qwp_hash::hash32;

fn main() {
    let generators = [1_i8, -2, 3, -4, 5, -6, 7, -7];
    let Ok(braid) = Braid::from_generators(&generators) else {
        return;
    };
    let braid_bytes = braid.to_bytes();
    let polynomial_bytes = [0_u8; qwp_core::PUBLIC_KEY_BYTES];
    let message = [0_u8; 1024];

    bench("braid/from_generators", 1_000_000, || {
        let result = Braid::from_generators(black_box(&generators));
        black_box(result.is_ok());
    });
    bench("braid/from_bytes", 1_000_000, || {
        let result = Braid::from_bytes(black_box(&braid_bytes));
        black_box(result.is_ok());
    });
    bench("polynomial/from_bytes", 1_000_000, || {
        black_box(Polynomial::from_bytes(black_box(&polynomial_bytes)));
    });
    bench("blake3/1024", 100_000, || {
        black_box(hash32(black_box(&message)));
    });
}

fn bench<F>(name: &str, iterations: u32, mut operation: F)
where
    F: FnMut(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = start.elapsed();
    let total_nanos = elapsed.as_nanos();
    let divisor = u128::from(iterations);
    let nanos_per_operation = total_nanos / divisor;
    println!("{name}: {nanos_per_operation} ns/op ({iterations} iterations)");
}
