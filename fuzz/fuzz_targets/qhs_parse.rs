//! libFuzzer target for QHS-1/2/3/4/4.2/5/6 fixed-layout parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qwp_crypto::{
    Qhs2Signature, Qhs3Signature, Qhs42Signature, Qhs4Signature, Qhs5Signature, Qhs6Signature,
    QhsSignature,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 7 {
        0 => {
            let mut fixed = [0_u8; 2_408];
            let len = fixed.len().min(rest.len());
            fixed[..len].copy_from_slice(&rest[..len]);
            let _ = QhsSignature::from_bytes(fixed);
        }
        1 => {
            let mut fixed = [0_u8; 1_704];
            let len = fixed.len().min(rest.len());
            fixed[..len].copy_from_slice(&rest[..len]);
            let _ = Qhs2Signature::from_bytes(fixed);
        }
        2 => {
            let mut fixed = [0_u8; 1_832];
            let len = fixed.len().min(rest.len());
            fixed[..len].copy_from_slice(&rest[..len]);
            let _ = Qhs3Signature::from_bytes(fixed);
        }
        3 => {
            let _ = Qhs4Signature::from_slice(rest);
        }
        4 => {
            let _ = Qhs42Signature::from_slice(rest);
        }
        5 => {
            let _ = Qhs5Signature::from_slice(rest);
        }
        _ => {
            let _ = Qhs6Signature::from_slice(rest);
        }
    }
});
