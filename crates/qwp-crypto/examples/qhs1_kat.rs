//! Prints the QHS-1 known-answer signature hash.

#![forbid(unsafe_code)]

use qwp_crypto::qhs_keygen;
use qwp_hash::hash32;

fn main() {
    let seed = [7_u8; 32];
    let Ok((mut private_key, _public_key)) = qhs_keygen(&seed) else {
        return;
    };
    let Ok(signature) = private_key.sign(b"qWp QHS-1 KAT") else {
        return;
    };
    println!("{:?}", hash32(&signature.to_bytes()));
}
