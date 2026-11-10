use qwp_classical::{Ed25519PrivateKey, Ed25519PublicKey};
use qwp_crypto::{qhs5_keygen, qhs6_keygen};

#[test]
fn ed25519_empty_message() {
    let private = Ed25519PrivateKey::from_seed([7_u8; 32]);
    let public = private.public_key();
    let signature = private.sign(b"");
    assert!(public.verify(b"", &signature).is_ok());
}

#[test]
fn qhs5_empty_message() {
    let (mut private, public) = qhs5_keygen(&[7_u8; 64]).unwrap();
    let signature = private.sign(b"").unwrap();
    assert!(public.verify(b"", &signature).is_ok());
}

#[test]
fn qhs6_one_byte_message() {
    let (mut private, public) = qhs6_keygen(&[7_u8; 64], &[7_u8; 32]).unwrap();
    let signature = private.sign(b"a").unwrap();
    assert!(public.verify(b"a", &signature).is_ok());
}

#[test]
fn ed25519_public_round_trip() {
    let private = Ed25519PrivateKey::from_seed([7_u8; 32]);
    let public = private.public_key();
    let bytes = public.to_bytes();
    let parsed = Ed25519PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, public);
}
