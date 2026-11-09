//! QHS-6 known-answer hybrid sign/verify test.

#![forbid(unsafe_code)]

use qwp_core::CryptoError;
use qwp_crypto::{
    Qhs6PrivateKey, Qhs6PublicKey, Qhs6Signature, qhs6_keygen, qhs6_keygen_from_leaves,
};
use qwp_hash::hash32;

const QHS5_SEED: [u8; 64] = [7_u8; 64];
const ED_SEED: [u8; 32] = [9_u8; 32];

#[test]
fn qhs6_known_answer_sign_and_verify() {
    let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
    let signature = private_key.sign(b"qWp QHS-6 KAT").unwrap();
    assert_eq!(public_key.verify(b"qWp QHS-6 KAT", &signature), Ok(()));
    assert_eq!(
        std::format!("{:?}", hash32(&signature.to_bytes())),
        "Hash32(b93cdeb0897a04dc584bd744cbfa25329124d85479c5bead28a0aa471e971974)"
    );
    assert_eq!(
        public_key.verify(b"qWp QHS-6 wrong", &signature),
        Err(CryptoError::VerificationFailed)
    );

    let public_bytes = public_key.to_bytes();
    let parsed_public = Qhs6PublicKey::from_bytes(&public_bytes).unwrap();
    assert_eq!(parsed_public, public_key);
    assert!(parsed_public.qhs5_public_key().is_ok());
    assert!(parsed_public.ed25519_public_key().is_ok());

    let private_bytes = private_key.to_bytes();
    let parsed_private = Qhs6PrivateKey::from_bytes(&private_bytes).unwrap();
    assert_eq!(parsed_private.qhs5_seed(), private_key.qhs5_seed());
    assert_eq!(parsed_private.next_leaf(), private_key.next_leaf());

    let signature_bytes = signature.to_bytes();
    assert_eq!(Qhs6Signature::from_slice(&signature_bytes), Ok(signature));

    let mut bad_public = public_bytes;
    bad_public[0] ^= 1;
    assert!(Qhs6PublicKey::from_bytes(&bad_public).is_err());
    let mut bad_private = private_bytes;
    bad_private[0] ^= 1;
    assert!(Qhs6PrivateKey::from_bytes(&bad_private).is_err());
    assert!(Qhs6Signature::from_slice(&signature_bytes[..100]).is_err());

    let mut tampered = signature.to_bytes();
    tampered[100] ^= 1;
    assert_eq!(
        public_key.verify(
            b"qWp QHS-6 KAT",
            &Qhs6Signature::from_slice(&tampered).unwrap()
        ),
        Err(CryptoError::VerificationFailed)
    );

    let leaves = qwp_crypto::qhs5_leaves(&QHS5_SEED).unwrap();
    let (mut cached, cached_public) =
        qhs6_keygen_from_leaves(&QHS5_SEED, &ED_SEED, &leaves).unwrap();
    assert_eq!(cached_public, public_key);
    let cached_signature = cached.sign_with_leaves(b"qWp QHS-6 KAT", &leaves).unwrap();
    assert_eq!(cached_signature, signature);
}
