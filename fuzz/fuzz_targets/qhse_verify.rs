//! libFuzzer target for the QHS-E verifier profile.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};

fn fixed_key(selector: u8, source: &[u8]) -> [u8; 64] {
    let mut key = [0_u8; 64];
    let (version, height) = match selector % 4 {
        0 => (1, 8),
        1 => (2, 8),
        2 | 3 => (3, 12),
        _ => (0, 0),
    };
    key[0] = version;
    key[1] = version;
    key[2] = height;
    key[3] = 0;
    let len = key.len().min(source.len());
    key[..len].copy_from_slice(&source[..len]);
    // Keep the reserved public-key tail canonical so the fuzzer reaches the
    // checksum/WOTS/Merkle paths instead of stopping at the header.
    key[36..].fill(0);
    key
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let (message, signature) = rest.split_at(rest.len().min(32));

    // Selectors 0-3 use a canonical header and zero reserved tail. Selectors
    // 4-7 use fully random key bytes to fuzz the header/tail rejection paths.
    let key = if selector < 4 {
        fixed_key(selector, signature)
    } else {
        let mut key = [0_u8; 64];
        let len = key.len().min(signature.len());
        key[..len].copy_from_slice(&signature[..len]);
        key
    };

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
