//! libFuzzer target for the QHS-E verifier profile.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let (message, signature) = rest.split_at(rest.len().min(32));
    let mut key = [0_u8; 64];
    let key_len = key.len().min(signature.len());
    key[..key_len].copy_from_slice(&signature[..key_len]);

    match selector % 4 {
        0 => {
            let mut fixed = [0_u8; 2_408];
            let len = fixed.len().min(signature.len());
            fixed[..len].copy_from_slice(&signature[..len]);
            let _ = verify_qhs1(&key, message, &fixed);
        }
        1 => {
            let mut fixed = [0_u8; 1_704];
            let len = fixed.len().min(signature.len());
            fixed[..len].copy_from_slice(&signature[..len]);
            let _ = verify_qhs2(&key, message, &fixed);
        }
        2 => {
            let mut fixed = [0_u8; 1_832];
            let len = fixed.len().min(signature.len());
            fixed[..len].copy_from_slice(&signature[..len]);
            let _ = verify_qhs3(&key, message, &fixed);
        }
        _ => {
            let mut fixed = [0_u8; 1_832];
            let len = fixed.len().min(signature.len());
            fixed[..len].copy_from_slice(&signature[..len]);
            let _ = verify_qhs31(&key, message, &fixed);
        }
    }
});
