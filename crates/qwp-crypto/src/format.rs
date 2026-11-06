//! Fixed-size private key, public key, and signature wrappers.

use core::fmt;
use core::mem::size_of;

use qwp_core::{
    Braid, CryptoError, PRIVATE_KEY_BYTES, PUBLIC_KEY_BYTES, Polynomial, SIGNATURE_BYTES,
};

/// A secret braid key.
///
/// The key is not `Clone`, is not printable, and is wiped best-effort on drop.
pub struct PrivateKey {
    braid: Braid,
}

impl PrivateKey {
    /// Wraps a validated braid as a private key.
    #[must_use]
    #[inline]
    pub const fn from_braid(braid: Braid) -> Self {
        Self { braid }
    }

    /// Parses a private key from its exact 40-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error when the braid is malformed.
    #[inline]
    pub fn from_bytes(bytes: &[u8; PRIVATE_KEY_BYTES]) -> Result<Self, CryptoError> {
        Ok(Self {
            braid: Braid::from_bytes(bytes)?,
        })
    }

    /// Serializes the private key into its exact 40-byte representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; PRIVATE_KEY_BYTES] {
        self.braid.to_bytes()
    }

    /// Returns the underlying braid.
    #[must_use]
    #[inline]
    pub const fn as_braid(&self) -> &Braid {
        &self.braid
    }

    /// Returns the active crossing count.
    #[must_use]
    #[inline]
    pub fn len(&self) -> u8 {
        self.braid.len()
    }

    /// Returns `true` when the key is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.braid.is_empty()
    }
}

impl Drop for PrivateKey {
    #[inline]
    fn drop(&mut self) {
        self.braid.clear();
    }
}

impl fmt::Debug for PrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKey")
            .field("len", &self.braid.len())
            .finish_non_exhaustive()
    }
}

/// A public polynomial key.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    polynomial: Polynomial,
}

impl PublicKey {
    /// Wraps a polynomial as a public key.
    #[must_use]
    #[inline]
    pub const fn from_polynomial(polynomial: Polynomial) -> Self {
        Self { polynomial }
    }

    /// Parses a public key from its exact 516-byte representation.
    #[must_use]
    #[inline]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_BYTES]) -> Self {
        Self {
            polynomial: Polynomial::from_bytes(bytes),
        }
    }

    /// Serializes the public key into its exact 516-byte representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.polynomial.to_bytes()
    }

    /// Returns the underlying polynomial.
    #[must_use]
    #[inline]
    pub const fn as_polynomial(&self) -> &Polynomial {
        &self.polynomial
    }
}

/// A fixed-size signature.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    bytes: [u8; SIGNATURE_BYTES],
}

impl Signature {
    /// Creates a signature from its exact 160-byte representation.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Returns the exact 160-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.bytes
    }

    /// Returns `true` when every byte is zero.
    #[must_use]
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }
}

const _: [(); PRIVATE_KEY_BYTES] = [(); size_of::<PrivateKey>()];
const _: [(); PUBLIC_KEY_BYTES] = [(); size_of::<PublicKey>()];
const _: [(); SIGNATURE_BYTES] = [(); size_of::<Signature>()];

#[cfg(test)]
mod tests {
    use super::{PrivateKey, PublicKey, Signature};
    use qwp_core::{Braid, Polynomial};

    #[test]
    fn private_key_round_trip() {
        let braid = Braid::from_generators(&[1, -2, 7]).unwrap();
        let key = PrivateKey::from_braid(braid);
        let bytes = key.to_bytes();
        let parsed = PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed.as_braid().as_slice(), &[1, -2, 7]);
    }

    #[test]
    fn public_key_round_trip() {
        let mut polynomial = Polynomial::new();
        polynomial.set_coefficient(0, 42).unwrap();
        let key = PublicKey::from_polynomial(polynomial);
        let bytes = key.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes);
        assert_eq!(parsed, key);
    }

    #[test]
    fn signature_round_trip() {
        let mut bytes = [0_u8; 160];
        bytes[0] = 1;
        bytes[159] = 2;
        let signature = Signature::from_bytes(bytes);
        assert_eq!(signature.to_bytes(), bytes);
        assert!(!signature.is_zero());
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let braid = Braid::from_generators(&[1, 2, 3]).unwrap();
        let key = PrivateKey::from_braid(braid);
        let debug = std::format!("{key:?}");
        assert!(debug.contains("PrivateKey"));
        assert!(!debug.contains("crossings"));
    }

    #[test]
    fn empty_private_key_and_invalid_bytes() {
        let key = PrivateKey::from_braid(Braid::new());
        assert!(key.is_empty());
        let nonempty = PrivateKey::from_braid(Braid::from_generators(&[1]).unwrap());
        assert!(!nonempty.is_empty());
        let mut bytes = [0_u8; 40];
        bytes[32..40].copy_from_slice(&33_u64.to_le_bytes());
        assert!(PrivateKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn zero_signature_and_bytes() {
        let signature = Signature::from_bytes([0_u8; 160]);
        assert!(signature.is_zero());
        assert_eq!(signature.as_bytes(), &[0_u8; 160]);
    }

    #[test]
    fn public_key_as_polynomial() {
        let polynomial = Polynomial::new();
        let key = PublicKey::from_polynomial(polynomial);
        assert_eq!(key.as_polynomial(), &polynomial);
    }
}
