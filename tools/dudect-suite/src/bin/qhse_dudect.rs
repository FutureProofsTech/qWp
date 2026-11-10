//! DudeCT timing probes for the QHS-E verifier.
//!
//! Verification operates on public data. These probes check that valid
//! signatures with different Merkle leaf indices take indistinguishable time.
//! A positive-control probe measures an early checksum rejection.

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use qwp_crypto::{qhs2_keygen, qhs3_keygen, qhs_keygen};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3};

const SEED: [u8; 32] = [7_u8; 32];
const MESSAGE: &[u8] = b"qWp QHS-E dudect message";

fn qhse_valid_leaf_order(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let (mut private, public) = qhs_keygen(&SEED).unwrap();
    let first = private.sign(MESSAGE).unwrap().to_bytes();
    let second = private.sign(MESSAGE).unwrap().to_bytes();
    let public = public.to_bytes();
    for index in 0..20_000 {
        let class = if index % 2 == 0 {
            Class::Left
        } else {
            Class::Right
        };
        let signature = if index % 2 == 0 { &first } else { &second };
        runner.run_one(class, || {
            let _ = verify_qhs1(&public, MESSAGE, signature);
        });
    }
}

fn qhse_qhs2_valid(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let (mut private, public) = qhs2_keygen(&SEED).unwrap();
    let first = private.sign(MESSAGE).unwrap().to_bytes();
    let second = private.sign(MESSAGE).unwrap().to_bytes();
    let public = public.to_bytes();
    for index in 0..10_000 {
        let class = if index % 2 == 0 {
            Class::Left
        } else {
            Class::Right
        };
        let signature = if index % 2 == 0 { &first } else { &second };
        runner.run_one(class, || {
            let _ = verify_qhs2(&public, MESSAGE, signature);
        });
    }
}

fn qhse_qhs3_valid(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let (mut private, public) = qhs3_keygen(&SEED).unwrap();
    let first = private.sign(MESSAGE).unwrap().to_bytes();
    let second = private.sign(MESSAGE).unwrap().to_bytes();
    let public = public.to_bytes();
    for index in 0..5_000 {
        let class = if index % 2 == 0 {
            Class::Left
        } else {
            Class::Right
        };
        let signature = if index % 2 == 0 { &first } else { &second };
        runner.run_one(class, || {
            let _ = verify_qhs3(&public, MESSAGE, signature);
        });
    }
}

fn qhse_checksum_reject_control(runner: &mut CtRunner, _rng: &mut BenchRng) {
    let (mut private, public) = qhs_keygen(&SEED).unwrap();
    let valid = private.sign(MESSAGE).unwrap().to_bytes();
    let mut invalid = valid;
    invalid[2_404] ^= 1;
    let public = public.to_bytes();
    for index in 0..20_000 {
        let class = if index % 2 == 0 {
            Class::Left
        } else {
            Class::Right
        };
        let signature = if index % 2 == 0 { &valid } else { &invalid };
        runner.run_one(class, || {
            let _ = verify_qhs1(&public, MESSAGE, signature);
        });
    }
}

ctbench_main!(
    qhse_valid_leaf_order,
    qhse_qhs2_valid,
    qhse_qhs3_valid,
    qhse_checksum_reject_control
);
