//! Kani proofs for the qWp foundation.

use qwp_core::{Braid, Polynomial};

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
