//! Differential tests: QHS-E vs the qwp-crypto verifiers.

#![forbid(unsafe_code)]

use qwp_crypto::{
    Qhs2Signature, Qhs3Signature, QhsSignature, qhs_keygen, qhs2_keygen, qhs3_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};

const SEED: [u8; 32] = [7_u8; 32];
const OTHER_SEED: [u8; 32] = [9_u8; 32];

#[test]
fn qhs1_matches_crypto_verifier() {
    let (mut private_key, public_key) = qhs_keygen(&SEED).unwrap();
    let message = b"qWp QHS-E QHS-1 differential";
    let signature = private_key.sign(message).unwrap();
    let public_bytes = public_key.to_bytes();
    let signature_bytes = signature.to_bytes();
    assert_eq!(
        verify_qhs1(&public_bytes, message, &signature_bytes),
        Ok(())
    );
    assert_eq!(public_key.verify(message, &signature), Ok(()));
    assert!(verify_qhs1(&public_bytes, b"wrong", &signature_bytes).is_err());

    for offset in [0_usize, 1, 2, 3, 4, 100, 2_147, 2_148, 2_403, 2_404, 2_407] {
        let mut tampered = signature_bytes;
        tampered[offset] ^= 1;
        assert_eq!(
            verify_qhs1(&public_bytes, message, &tampered).is_ok(),
            public_key
                .verify(message, &QhsSignature::from_bytes(tampered))
                .is_ok()
        );
        assert!(verify_qhs1(&public_bytes, message, &tampered).is_err());
    }

    let (_, other_public) = qhs_keygen(&OTHER_SEED).unwrap();
    assert!(verify_qhs1(&other_public.to_bytes(), message, &signature_bytes).is_err());
}

#[test]
fn qhs2_matches_crypto_verifier() {
    let (mut private_key, public_key) = qhs2_keygen(&SEED).unwrap();
    let message = b"qWp QHS-E QHS-2 differential";
    let signature = private_key.sign(message).unwrap();
    let public_bytes = public_key.to_bytes();
    let signature_bytes = signature.to_bytes();
    assert_eq!(
        verify_qhs2(&public_bytes, message, &signature_bytes),
        Ok(())
    );
    assert_eq!(public_key.verify(message, &signature), Ok(()));
    assert!(verify_qhs2(&public_bytes, b"wrong", &signature_bytes).is_err());

    for offset in [0_usize, 1, 2, 3, 4, 100, 1_443, 1_444, 1_699, 1_700, 1_703] {
        let mut tampered = signature_bytes;
        tampered[offset] ^= 1;
        assert_eq!(
            verify_qhs2(&public_bytes, message, &tampered).is_ok(),
            public_key
                .verify(message, &Qhs2Signature::from_bytes(tampered))
                .is_ok()
        );
        assert!(verify_qhs2(&public_bytes, message, &tampered).is_err());
    }

    let (_, other_public) = qhs2_keygen(&OTHER_SEED).unwrap();
    assert!(verify_qhs2(&other_public.to_bytes(), message, &signature_bytes).is_err());
}

#[test]
fn qhs3_and_qhs31_match_crypto_verifier() {
    let (mut private_key, public_key) = qhs3_keygen(&SEED).unwrap();
    let message = b"qWp QHS-E QHS-3 differential";
    let signature = private_key.sign(message).unwrap();
    let public_bytes = public_key.to_bytes();
    let signature_bytes = signature.to_bytes();
    assert_eq!(
        verify_qhs3(&public_bytes, message, &signature_bytes),
        Ok(())
    );
    assert_eq!(
        verify_qhs31(&public_bytes, message, &signature_bytes),
        Ok(())
    );
    assert_eq!(public_key.verify(message, &signature), Ok(()));
    assert!(verify_qhs3(&public_bytes, b"wrong", &signature_bytes).is_err());

    for offset in [0_usize, 1, 2, 3, 4, 100, 1_443, 1_444, 1_827, 1_828, 1_831] {
        let mut tampered = signature_bytes;
        tampered[offset] ^= 1;
        assert_eq!(
            verify_qhs3(&public_bytes, message, &tampered).is_ok(),
            public_key
                .verify(message, &Qhs3Signature::from_bytes(tampered))
                .is_ok()
        );
        assert!(verify_qhs3(&public_bytes, message, &tampered).is_err());
    }

    let (_, other_public) = qhs3_keygen(&OTHER_SEED).unwrap();
    assert!(verify_qhs3(&other_public.to_bytes(), message, &signature_bytes).is_err());
}

#[test]
fn random_signatures_match_crypto_verifier() {
    let (_, public1) = qhs_keygen(&SEED).unwrap();
    let (_, public2) = qhs2_keygen(&SEED).unwrap();
    let (_, public3) = qhs3_keygen(&SEED).unwrap();
    let mut state = 0x1234_5678_9abc_def0_u64;
    for _ in 0..8 {
        let mut sig1 = [0_u8; 2_408];
        fill(&mut sig1, &mut state);
        assert_eq!(
            verify_qhs1(&public1.to_bytes(), b"random", &sig1).is_ok(),
            public1
                .verify(b"random", &QhsSignature::from_bytes(sig1))
                .is_ok()
        );

        let mut sig2 = [0_u8; 1_704];
        fill(&mut sig2, &mut state);
        assert_eq!(
            verify_qhs2(&public2.to_bytes(), b"random", &sig2).is_ok(),
            public2
                .verify(b"random", &Qhs2Signature::from_bytes(sig2))
                .is_ok()
        );

        let mut sig3 = [0_u8; 1_832];
        fill(&mut sig3, &mut state);
        assert_eq!(
            verify_qhs3(&public3.to_bytes(), b"random", &sig3).is_ok(),
            public3
                .verify(b"random", &Qhs3Signature::from_bytes(sig3))
                .is_ok()
        );
    }
}

fn fill(bytes: &mut [u8], state: &mut u64) {
    for byte in bytes {
        *state ^= state.wrapping_shl(13);
        *state ^= state.wrapping_shr(7);
        *state ^= state.wrapping_shl(17);
        *byte = state.to_le_bytes()[0];
    }
}

#[test]
fn multiple_leaves_match_crypto_verifier() {
    let (mut private1, public1) = qhs_keygen(&SEED).unwrap();
    let (mut private2, public2) = qhs2_keygen(&SEED).unwrap();
    let (mut private3, public3) = qhs3_keygen(&SEED).unwrap();
    for index in 0..4_u8 {
        let message = [index; 16];
        let signature1 = private1.sign(&message).unwrap();
        assert_eq!(
            verify_qhs1(&public1.to_bytes(), &message, &signature1.to_bytes()),
            Ok(())
        );
        let signature2 = private2.sign(&message).unwrap();
        assert_eq!(
            verify_qhs2(&public2.to_bytes(), &message, &signature2.to_bytes()),
            Ok(())
        );
        let signature3 = private3.sign(&message).unwrap();
        assert_eq!(
            verify_qhs3(&public3.to_bytes(), &message, &signature3.to_bytes()),
            Ok(())
        );
        assert_eq!(
            verify_qhs31(&public3.to_bytes(), &message, &signature3.to_bytes()),
            Ok(())
        );
    }
}

#[test]
fn qhs31_rejects_invalid_signatures() {
    let (mut private_key, public_key) = qhs3_keygen(&SEED).unwrap();
    let message = b"qWp QHS-E QHS-3.1 negative";
    let signature = private_key.sign(message).unwrap();
    let public_bytes = public_key.to_bytes();
    let signature_bytes = signature.to_bytes();
    assert_eq!(
        verify_qhs31(&public_bytes, message, &signature_bytes),
        Ok(())
    );
    assert!(verify_qhs31(&public_bytes, b"wrong", &signature_bytes).is_err());
    let mut tampered = signature_bytes;
    tampered[100] ^= 1;
    assert!(verify_qhs31(&public_bytes, message, &tampered).is_err());
}
