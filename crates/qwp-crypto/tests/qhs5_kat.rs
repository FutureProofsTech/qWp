//! QHS-5 known-answer sign/verify test.
//!
//! This test runs in debug builds too, so mutation testing can exercise the
//! full signing, verification, parser, and accessor paths without relying on
//! release-only tests.

#![forbid(unsafe_code)]

use qwp_core::CryptoError;
use qwp_crypto::{Qhs5PrivateKey, Qhs5PublicKey, Qhs5Signature, qhs5_keygen};
use qwp_hash::hash32;

const SEED: [u8; 64] = [7_u8; 64];

#[test]
fn qhs5_known_answer_sign_and_verify() {
    let (mut private_key, public_key) = qhs5_keygen(&SEED).unwrap();
    let signature = private_key.sign(b"qWp QHS-5 KAT").unwrap();
    assert_eq!(public_key.verify(b"qWp QHS-5 KAT", &signature), Ok(()));
    assert_eq!(
        std::format!("{:?}", hash32(&signature.to_bytes())),
        "Hash32(104c828b2172442e32d3ffe8448a9d6358b4a48fe7573a6a7367ec5986d6aada)"
    );
    assert_eq!(
        public_key.verify(b"qWp QHS-5 wrong", &signature),
        Err(CryptoError::VerificationFailed)
    );

    let public_bytes = public_key.to_bytes();
    let parsed_public = Qhs5PublicKey::from_bytes(&public_bytes).unwrap();
    assert_eq!(parsed_public, public_key);
    assert_eq!(parsed_public.root(), public_key.root());
    assert_eq!(parsed_public.verify(b"qWp QHS-5 KAT", &signature), Ok(()));

    let private_bytes = private_key.to_bytes();
    let parsed_private = Qhs5PrivateKey::from_bytes(&private_bytes).unwrap();
    assert_eq!(parsed_private.seed(), private_key.seed());
    assert_eq!(parsed_private.next_leaf(), private_key.next_leaf());

    let signature_bytes = signature.to_bytes();
    assert_eq!(Qhs5Signature::from_slice(&signature_bytes), Ok(signature));

    let mut bad_public = public_bytes;
    bad_public[0] ^= 1;
    assert!(Qhs5PublicKey::from_bytes(&bad_public).is_err());
    let mut bad_private = private_bytes;
    bad_private[0] ^= 1;
    assert!(Qhs5PrivateKey::from_bytes(&bad_private).is_err());
    assert!(Qhs5Signature::from_slice(&signature_bytes[..100]).is_err());

    let mut tampered = signature.to_bytes();
    tampered[100] ^= 1;
    assert_eq!(
        public_key.verify(b"qWp QHS-5 KAT", &Qhs5Signature::from_bytes(tampered)),
        Err(CryptoError::VerificationFailed)
    );
}
