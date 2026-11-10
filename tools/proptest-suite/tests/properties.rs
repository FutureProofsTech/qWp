//! Proptest property suite for qWp signatures and the QHS-E verifier.

use proptest::prelude::*;
use qwp_crypto::{
    Qhs2Signature, Qhs3Signature, Qhs42Signature, Qhs4Signature, Qhs5Signature, Qhs6Signature,
    QhsSignature, qhs2_keygen, qhs3_keygen, qhs6_keygen, qhs_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};

const SEED: [u8; 32] = [7_u8; 32];
const MESSAGE: &[u8] = b"qWp proptest fixed message";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn qhse_rejects_any_other_message(message in proptest::collection::vec(any::<u8>(), 0..256)) {
        prop_assume!(message.as_slice() != MESSAGE);
        let (mut private1, public1) = qhs_keygen(&SEED).unwrap();
        let signature1 = private1.sign(MESSAGE).unwrap().to_bytes();
        prop_assert!(verify_qhs1(&public1.to_bytes(), MESSAGE, &signature1).is_ok());
        prop_assert!(verify_qhs1(&public1.to_bytes(), &message, &signature1).is_err());

        let (mut private2, public2) = qhs2_keygen(&SEED).unwrap();
        let signature2 = private2.sign(MESSAGE).unwrap().to_bytes();
        prop_assert!(verify_qhs2(&public2.to_bytes(), MESSAGE, &signature2).is_ok());
        prop_assert!(verify_qhs2(&public2.to_bytes(), &message, &signature2).is_err());

        let (mut private3, public3) = qhs3_keygen(&SEED).unwrap();
        let signature3 = private3.sign(MESSAGE).unwrap().to_bytes();
        prop_assert!(verify_qhs3(&public3.to_bytes(), MESSAGE, &signature3).is_ok());
        prop_assert!(verify_qhs31(&public3.to_bytes(), MESSAGE, &signature3).is_ok());
        prop_assert!(verify_qhs3(&public3.to_bytes(), &message, &signature3).is_err());
    }

    #[test]
    fn qhse_rejects_single_byte_mutations(position in any::<prop::sample::Index>(), value in any::<u8>()) {
        let (mut private1, public1) = qhs_keygen(&SEED).unwrap();
        let mut signature1 = private1.sign(MESSAGE).unwrap().to_bytes();
        let index = position.index(signature1.len());
        signature1[index] ^= value | 1;
        prop_assert!(verify_qhs1(&public1.to_bytes(), MESSAGE, &signature1).is_err());

        let (mut private2, public2) = qhs2_keygen(&SEED).unwrap();
        let mut signature2 = private2.sign(MESSAGE).unwrap().to_bytes();
        let index = position.index(signature2.len());
        signature2[index] ^= value | 1;
        prop_assert!(verify_qhs2(&public2.to_bytes(), MESSAGE, &signature2).is_err());

        let (mut private3, public3) = qhs3_keygen(&SEED).unwrap();
        let mut signature3 = private3.sign(MESSAGE).unwrap().to_bytes();
        let index = position.index(signature3.len());
        signature3[index] ^= value | 1;
        prop_assert!(verify_qhs3(&public3.to_bytes(), MESSAGE, &signature3).is_err());
        prop_assert!(verify_qhs31(&public3.to_bytes(), MESSAGE, &signature3).is_err());
    }

    #[test]
    fn fixed_signature_parsers_round_trip(
        bytes1 in proptest::array::uniform::<_, 2_408>(any::<u8>()),
        bytes2 in proptest::array::uniform::<_, 1_704>(any::<u8>()),
        bytes3 in proptest::array::uniform::<_, 1_832>(any::<u8>()),
    ) {
        prop_assert_eq!(QhsSignature::from_bytes(bytes1).to_bytes(), bytes1);
        prop_assert_eq!(Qhs2Signature::from_bytes(bytes2).to_bytes(), bytes2);
        prop_assert_eq!(Qhs3Signature::from_bytes(bytes3).to_bytes(), bytes3);
    }

    #[test]
    fn variable_signature_parsers_round_trip(
        bytes4 in proptest::collection::vec(any::<u8>(), 0..32_768),
        bytes5 in proptest::collection::vec(any::<u8>(), 0..16_384),
        bytes6 in proptest::collection::vec(any::<u8>(), 0..16_384),
    ) {
        if let Ok(signature) = Qhs4Signature::from_slice(&bytes4) {
            let round_trip = signature.to_bytes();
            prop_assert_eq!(round_trip.as_slice(), bytes4.as_slice());
        }
        if let Ok(signature) = Qhs42Signature::from_slice(&bytes5) {
            let round_trip = signature.to_bytes();
            prop_assert_eq!(round_trip.as_slice(), bytes5.as_slice());
        }
        if let Ok(signature) = Qhs5Signature::from_slice(&bytes6) {
            let round_trip = signature.to_bytes();
            prop_assert_eq!(round_trip.as_slice(), bytes6.as_slice());
        }
        if let Ok(signature) = Qhs6Signature::from_slice(&bytes6) {
            let round_trip = signature.to_bytes();
            prop_assert_eq!(round_trip.as_slice(), bytes6.as_slice());
        }
    }

    #[test]
    fn qhs6_hybrid_round_trip(message in proptest::collection::vec(any::<u8>(), 0..256)) {
        let (mut private, public) = qhs6_keygen(&[7_u8; 64], &SEED).unwrap();
        let signature = private.sign(&message).unwrap();
        prop_assert!(public.verify(&message, &signature).is_ok());
        let mut other = message.clone();
        other.push(0);
        prop_assert!(public.verify(&other, &signature).is_err());
    }
}
