//! libFuzzer target for the QHS-6 hybrid parser and component boundaries.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qwp_crypto::{Qhs6Signature, QhsSignature};
use qwp_classical::Ed25519Signature;

fuzz_target!(|data: &[u8]| {
    let _ = Qhs6Signature::from_slice(data);
    let mut qhs = [0_u8; 2_408];
    let len = qhs.len().min(data.len());
    qhs[..len].copy_from_slice(&data[..len]);
    let _ = QhsSignature::from_bytes(qhs);
    let _ = Ed25519Signature::from_slice(data);
});
