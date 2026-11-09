//! QHS-4 known-answer sign/verify test.
//!
//! This test runs in debug builds too, so mutation testing can exercise the
//! full signing, verification, parser, and accessor paths without relying on
//! release-only tests.

#![forbid(unsafe_code)]

use qwp_core::CryptoError;
use qwp_crypto::{Qhs4PrivateKey, Qhs4PublicKey, Qhs4Signature, qhs4_keygen};
use qwp_hash::hash32;

const SEED: [u8; 32] = [7_u8; 32];

#[test]
fn qhs4_known_answer_sign_and_verify() {
    let (private_key, public_key) = qhs4_keygen(&SEED).unwrap();
    let signature = private_key.sign(b"qWp QHS-4 KAT").unwrap();
    assert_eq!(public_key.verify(b"qWp QHS-4 KAT", &signature), Ok(()));
    assert_eq!(
        std::format!("{:?}", hash32(&signature.to_bytes())),
        "Hash32(43669f2fe1a86fcc52d2dbcc57e172917bc6ea9189b3404ffa9e1a046e8b1f95)"
    );
    assert_eq!(
        public_key.verify(b"qWp QHS-4 wrong", &signature),
        Err(CryptoError::VerificationFailed)
    );

    let public_bytes = public_key.to_bytes();
    let parsed_public = Qhs4PublicKey::from_bytes(&public_bytes).unwrap();
    assert_eq!(parsed_public, public_key);
    assert_eq!(parsed_public.seed(), public_key.seed());
    assert_eq!(parsed_public.root(), public_key.root());
    assert_eq!(parsed_public.verify(b"qWp QHS-4 KAT", &signature), Ok(()));

    let private_bytes = private_key.to_bytes();
    let parsed_private = Qhs4PrivateKey::from_bytes(&private_bytes).unwrap();
    assert_eq!(parsed_private.sk_seed(), private_key.sk_seed());
    assert_eq!(parsed_private.pk_seed(), private_key.pk_seed());

    let signature_bytes = signature.to_bytes();
    assert_eq!(Qhs4Signature::from_slice(&signature_bytes), Ok(signature));

    let mut bad_public = public_bytes;
    bad_public[0] ^= 1;
    assert!(Qhs4PublicKey::from_bytes(&bad_public).is_err());
    let mut bad_private = private_bytes;
    bad_private[0] ^= 1;
    assert!(Qhs4PrivateKey::from_bytes(&bad_private).is_err());
    assert!(Qhs4Signature::from_slice(&signature_bytes[..100]).is_err());

    let mut tampered = signature.to_bytes();
    tampered[100] ^= 1;
    assert_eq!(
        public_key.verify(b"qWp QHS-4 KAT", &Qhs4Signature::from_bytes(tampered)),
        Err(CryptoError::VerificationFailed)
    );
}
