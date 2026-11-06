//! Foundation integration tests.

use qwp_core::{
    BRAID_BYTES, Braid, CryptoError, MAX_CROSSINGS, PUBLIC_KEY_BYTES, Polynomial, SIGNATURE_BYTES,
};
use qwp_crypto::{
    PrivateKey, PublicKey, QHS2_SIGNATURE_BYTES, QHS3_SIGNATURE_BYTES, Qhs2Signature,
    Qhs3Signature, QhsSignature, Signature, qhs_keygen, qhs2_keygen, qhs3_keygen_from_leaves,
};
use qwp_hash::hash32;
use qwp_platform::{HostEntropy, qhs3_leaves_parallel};

#[test]
fn fixed_layout_sizes() {
    assert_eq!(core::mem::size_of::<Braid>(), BRAID_BYTES);
    assert_eq!(core::mem::size_of::<Polynomial>(), PUBLIC_KEY_BYTES);
    assert_eq!(core::mem::size_of::<Signature>(), SIGNATURE_BYTES);
}

#[test]
fn braid_round_trip() {
    let braid = Braid::from_generators(&[1, -2, 7, -7]).unwrap();
    let bytes = braid.to_bytes();
    let parsed = Braid::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, braid);
}

#[test]
fn braid_rejects_invalid_input() {
    assert_eq!(
        Braid::from_generators(&[0]),
        Err(CryptoError::InvalidGenerator)
    );
    assert_eq!(
        Braid::from_generators(&[8]),
        Err(CryptoError::InvalidGenerator)
    );
    let too_long = [1_i8; MAX_CROSSINGS + 1];
    assert_eq!(
        Braid::from_generators(&too_long),
        Err(CryptoError::InvalidLength)
    );
}

#[test]
fn polynomial_round_trip() {
    let mut polynomial = Polynomial::new();
    polynomial.set_coefficient(-64, i32::MIN).unwrap();
    polynomial.set_coefficient(0, 42).unwrap();
    polynomial.set_coefficient(64, i32::MAX).unwrap();
    let bytes = polynomial.to_bytes();
    assert_eq!(Polynomial::from_bytes(&bytes), polynomial);
}

#[test]
fn key_and_signature_formats() {
    let braid = Braid::from_generators(&[1, -2, 7]).unwrap();
    let private_key = PrivateKey::from_braid(braid);
    let private_bytes = private_key.to_bytes();
    assert_eq!(PrivateKey::from_bytes(&private_bytes).unwrap().len(), 3);

    let public_key = PublicKey::from_polynomial(Polynomial::new());
    assert_eq!(PublicKey::from_bytes(&public_key.to_bytes()), public_key);

    let signature = Signature::from_bytes([0_u8; SIGNATURE_BYTES]);
    assert_eq!(Signature::from_bytes(signature.to_bytes()), signature);
}

#[test]
fn blake3_vectors() {
    assert_eq!(
        std::format!("{:?}", hash32(b"")),
        "Hash32(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262)"
    );
    assert_eq!(
        std::format!("{:?}", hash32(b"abc")),
        "Hash32(6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85)"
    );
}

#[test]
fn qhs1_sign_verify_round_trip() {
    let seed = [7_u8; 32];
    let (mut private_key, public_key) = qhs_keygen(&seed).unwrap();
    let signature = private_key.sign(b"qWp QHS-1 integration").unwrap();
    assert_eq!(
        public_key.verify(b"qWp QHS-1 integration", &signature),
        Ok(())
    );
    assert_eq!(signature.leaf_index(), Ok(0));
    assert_eq!(private_key.next_leaf(), 1);
}

#[test]
fn qhs1_rejects_tampering_and_wrong_message() {
    let seed = [7_u8; 32];
    let (mut private_key, public_key) = qhs_keygen(&seed).unwrap();
    let signature = private_key.sign(b"message-a").unwrap();
    assert!(public_key.verify(b"message-b", &signature).is_err());

    let mut bytes = signature.to_bytes();
    if let Some(byte) = bytes.get_mut(20) {
        *byte ^= 1;
    }
    let tampered = QhsSignature::from_bytes(bytes);
    assert!(public_key.verify(b"message-a", &tampered).is_err());
}

#[test]
fn qhs2_sign_verify_round_trip() {
    let seed = [7_u8; 32];
    let (mut private_key, public_key) = qhs2_keygen(&seed).unwrap();
    let signature = private_key.sign(b"qWp QHS-2 integration").unwrap();
    assert_eq!(
        public_key.verify(b"qWp QHS-2 integration", &signature),
        Ok(())
    );
    assert_eq!(signature.leaf_index(), Ok(0));
    assert_eq!(private_key.next_leaf(), 1);
    assert_eq!(signature.to_bytes().len(), QHS2_SIGNATURE_BYTES);
}

#[test]
fn qhs2_rejects_tampering_and_wrong_message() {
    let seed = [7_u8; 32];
    let (mut private_key, public_key) = qhs2_keygen(&seed).unwrap();
    let signature = private_key.sign(b"message-a").unwrap();
    assert!(public_key.verify(b"message-b", &signature).is_err());

    let mut bytes = signature.to_bytes();
    if let Some(byte) = bytes.get_mut(20) {
        *byte ^= 1;
    }
    let tampered = Qhs2Signature::from_bytes(bytes);
    assert!(public_key.verify(b"message-a", &tampered).is_err());
}

#[test]
fn qhs3_sign_verify_round_trip_and_tamper() {
    let seed = [7_u8; 32];
    let leaves = qhs3_leaves_parallel(&seed).unwrap();
    let (mut private_key, public_key) = qhs3_keygen_from_leaves(&seed, &leaves).unwrap();
    let signature = private_key
        .sign_with_leaves(b"qWp QHS-3 integration", &leaves)
        .unwrap();
    assert_eq!(
        public_key.verify(b"qWp QHS-3 integration", &signature),
        Ok(())
    );
    assert_eq!(signature.leaf_index(), Ok(0));
    assert_eq!(private_key.next_leaf(), 1);
    assert_eq!(signature.to_bytes().len(), QHS3_SIGNATURE_BYTES);
    assert!(public_key.verify(b"wrong", &signature).is_err());

    let mut bytes = signature.to_bytes();
    if let Some(byte) = bytes.get_mut(20) {
        *byte ^= 1;
    }
    let tampered = Qhs3Signature::from_bytes(bytes);
    assert!(
        public_key
            .verify(b"qWp QHS-3 integration", &tampered)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn host_entropy_fills() {
    let mut entropy = HostEntropy::open().unwrap();
    let mut output = [0_u8; 32];
    entropy.fill(&mut output).unwrap();
}
