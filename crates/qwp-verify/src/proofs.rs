//! Kani proofs for the qWp foundation.

use qwp_core::{Braid, Polynomial};
use qwp_crypto::{
    Qhs2PrivateKey, Qhs2PublicKey, Qhs2Signature, Qhs3PrivateKey, Qhs3PublicKey, Qhs3Signature,
    Qhs4PrivateKey, Qhs4PublicKey, Qhs4Signature, Qhs5PrivateKey, Qhs5PublicKey, Qhs5Signature,
    Qhs6PrivateKey, Qhs6Signature, Qhs42PrivateKey, Qhs42PublicKey, Qhs42Signature, QhsPrivateKey,
    QhsPublicKey, QhsSignature,
};

#[kani::proof]
fn braid_from_bytes_never_panics() {
    let bytes: [u8; qwp_core::BRAID_BYTES] = kani::any();
    let _result = Braid::from_bytes(&bytes);
}

#[kani::proof]
fn braid_round_trip_is_stable() {
    let bytes: [u8; qwp_core::BRAID_BYTES] = kani::any();
    if let Ok(braid) = Braid::from_bytes(&bytes) {
        let round_trip = braid.to_bytes();
        assert_eq!(Braid::from_bytes(&round_trip).ok(), Some(braid));
    }
}

#[kani::proof]
fn polynomial_round_trip_is_exact() {
    let bytes: [u8; qwp_core::PUBLIC_KEY_BYTES] = kani::any();
    let polynomial = Polynomial::from_bytes(&bytes);
    assert_eq!(polynomial.to_bytes(), bytes);
}

#[kani::proof]
fn qhs_public_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS_PUBLIC_KEY_BYTES] = kani::any();
    let _result = QhsPublicKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs_private_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS_PRIVATE_KEY_BYTES] = kani::any();
    let _result = QhsPrivateKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs_signature_leaf_index_never_panics() {
    let bytes: [u8; qwp_crypto::QHS_SIGNATURE_BYTES] = kani::any();
    let signature = QhsSignature::from_bytes(bytes);
    let _result = signature.leaf_index();
}

#[kani::proof]
fn qhs2_public_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS2_PUBLIC_KEY_BYTES] = kani::any();
    let _result = Qhs2PublicKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs2_private_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS2_PRIVATE_KEY_BYTES] = kani::any();
    let _result = Qhs2PrivateKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs2_signature_leaf_index_never_panics() {
    let bytes: [u8; qwp_crypto::QHS2_SIGNATURE_BYTES] = kani::any();
    let signature = Qhs2Signature::from_bytes(bytes);
    let _result = signature.leaf_index();
}

#[kani::proof]
fn qhs3_public_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS3_PUBLIC_KEY_BYTES] = kani::any();
    let _result = Qhs3PublicKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs3_private_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS3_PRIVATE_KEY_BYTES] = kani::any();
    let _result = Qhs3PrivateKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs3_signature_leaf_index_never_panics() {
    let bytes: [u8; qwp_crypto::QHS3_SIGNATURE_BYTES] = kani::any();
    let signature = Qhs3Signature::from_bytes(bytes);
    let _result = signature.leaf_index();
}

#[kani::proof]
fn qhs4_public_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS4_PUBLIC_KEY_BYTES] = kani::any();
    let _result = Qhs4PublicKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs4_private_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS4_PRIVATE_KEY_BYTES] = kani::any();
    let _result = Qhs4PrivateKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs4_signature_from_slice_checks_length() {
    let bytes = [0_u8; qwp_crypto::QHS4_SIGNATURE_BYTES];
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let result = Qhs4Signature::from_slice(&bytes[..length]);
    assert_eq!(result.is_ok(), length == qwp_crypto::QHS4_SIGNATURE_BYTES);
}

#[kani::proof]
fn qhs42_public_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS42_PUBLIC_KEY_BYTES] = kani::any();
    let _result = Qhs42PublicKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs42_private_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS42_PRIVATE_KEY_BYTES] = kani::any();
    let _result = Qhs42PrivateKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs42_signature_from_slice_checks_length() {
    let bytes = [0_u8; qwp_crypto::QHS42_SIGNATURE_BYTES];
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let result = Qhs42Signature::from_slice(&bytes[..length]);
    assert_eq!(result.is_ok(), length == qwp_crypto::QHS42_SIGNATURE_BYTES);
}

#[kani::proof]
fn qhs5_public_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS5_PUBLIC_KEY_BYTES] = kani::any();
    let _result = Qhs5PublicKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs5_private_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS5_PRIVATE_KEY_BYTES] = kani::any();
    let _result = Qhs5PrivateKey::from_bytes(&bytes);
}

#[kani::proof]
fn qhs5_signature_from_slice_checks_length() {
    let bytes = [0_u8; qwp_crypto::QHS5_SIGNATURE_BYTES];
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let result = Qhs5Signature::from_slice(&bytes[..length]);
    assert_eq!(result.is_ok(), length == qwp_crypto::QHS5_SIGNATURE_BYTES);
}

#[kani::proof]
fn qhs6_private_key_parse_never_panics() {
    let bytes: [u8; qwp_crypto::QHS6_PRIVATE_KEY_BYTES] = kani::any();
    let _result = Qhs6PrivateKey::from_bytes(&bytes);
}

#[kani::proof]
fn ed25519_signature_from_slice_checks_length() {
    let bytes = [0_u8; qwp_classical::ED25519_SIGNATURE_BYTES];
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let result = qwp_classical::Ed25519Signature::from_slice(&bytes[..length]);
    assert_eq!(
        result.is_ok(),
        length == qwp_classical::ED25519_SIGNATURE_BYTES
    );
}

#[kani::proof]
fn qhs6_signature_from_slice_checks_length() {
    let bytes = [0_u8; qwp_crypto::QHS6_SIGNATURE_BYTES];
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let result = Qhs6Signature::from_slice(&bytes[..length]);
    assert!(length == qwp_crypto::QHS6_SIGNATURE_BYTES || result.is_err());
}
