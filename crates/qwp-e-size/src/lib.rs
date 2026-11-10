//! QHS-E static-library size probe.
//!
//! This crate exists only to link the QHS-E verifier into a static library for
//! code-size evidence on embedded targets. It is not part of the production
//! verifier API.

#![no_std]
#![forbid(unsafe_code)]

use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[used]
static QHSE_SIZE_PROBE: [fn() -> u32; 4] = [probe_qhs1, probe_qhs2, probe_qhs3, probe_qhs31];

fn probe_qhs1() -> u32 {
    let public_key = [0_u8; 64];
    let signature = [0_u8; 2_408];
    match verify_qhs1(&public_key, b"size", &signature) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn probe_qhs2() -> u32 {
    let public_key = [0_u8; 64];
    let signature = [0_u8; 1_704];
    match verify_qhs2(&public_key, b"size", &signature) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn probe_qhs3() -> u32 {
    let public_key = [0_u8; 64];
    let signature = [0_u8; 1_832];
    match verify_qhs3(&public_key, b"size", &signature) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn probe_qhs31() -> u32 {
    let public_key = [0_u8; 64];
    let signature = [0_u8; 1_832];
    match verify_qhs31(&public_key, b"size", &signature) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
