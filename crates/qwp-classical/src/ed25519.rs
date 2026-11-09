//! Ed25519 (RFC 8032) with SHA-512.

use core::fmt;

use qwp_core::CryptoError;

use crate::edwards::Point;
use crate::scalar::Scalar;
use crate::sha512::{Sha512, sha512};

/// Ed25519 seed size.
pub const ED25519_SEED_BYTES: usize = 32;
/// Ed25519 public-key size.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
/// Ed25519 signature size.
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// An Ed25519 private key seed.
pub struct Ed25519PrivateKey {
    seed: [u8; ED25519_SEED_BYTES],
}

impl Ed25519PrivateKey {
    /// Creates a private key from a 32-byte seed.
    #[must_use]
    #[inline]
    pub const fn from_seed(seed: [u8; ED25519_SEED_BYTES]) -> Self {
        Self { seed }
    }

    /// Returns the seed.
    #[must_use]
    #[inline]
    pub const fn seed(&self) -> &[u8; ED25519_SEED_BYTES] {
        &self.seed
    }

    /// Derives the public key.
    #[must_use]
    #[inline]
    pub fn public_key(&self) -> Ed25519PublicKey {
        let (scalar, _, _) = expand(&self.seed);
        Ed25519PublicKey {
            bytes: Point::BASE.scalar_mul(&scalar).encode(),
        }
    }

    /// Signs a message.
    #[must_use]
    #[inline]
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let (a_bytes, a_scalar, prefix) = expand(&self.seed);
        let public = Point::BASE.scalar_mul(&a_bytes).encode();

        let mut hasher = Sha512::new();
        hasher.update(&prefix);
        hasher.update(message);
        let r = Scalar::from_hash64(&hasher.finalize());
        let r_bytes = r.to_bytes();
        let r_encoded = Point::BASE.scalar_mul(&r_bytes).encode();

        let mut hasher = Sha512::new();
        hasher.update(&r_encoded);
        hasher.update(&public);
        hasher.update(message);
        let k = Scalar::from_hash64(&hasher.finalize());
        let s = k.mul_add(a_scalar, r);

        let mut bytes = [0_u8; ED25519_SIGNATURE_BYTES];
        bytes[..32].copy_from_slice(&r_encoded);
        bytes[32..].copy_from_slice(&s.to_bytes());
        Ed25519Signature { bytes }
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ed25519PrivateKey")
            .finish_non_exhaustive()
    }
}

impl Drop for Ed25519PrivateKey {
    #[inline]
    fn drop(&mut self) {
        self.seed.fill(0);
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    bytes: [u8; ED25519_PUBLIC_KEY_BYTES],
}

impl Ed25519PublicKey {
    /// Parses and validates a 32-byte public key.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical encoding, an off-curve point, or a
    /// small-order point.
    #[inline]
    pub fn from_bytes(bytes: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        let point = Point::decode(bytes).ok_or(CryptoError::VerificationFailed)?;
        if point.is_small_order() {
            return Err(CryptoError::VerificationFailed);
        }
        Ok(Self { bytes: *bytes })
    }

    /// Returns the 32-byte encoding.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
        self.bytes
    }

    /// Verifies a signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerificationFailed`] for an invalid signature.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), CryptoError> {
        let public = Point::decode(&self.bytes).ok_or(CryptoError::VerificationFailed)?;
        if public.is_small_order() {
            return Err(CryptoError::VerificationFailed);
        }

        let mut r_bytes = [0_u8; 32];
        r_bytes.copy_from_slice(&signature.bytes[..32]);
        let r = Point::decode(&r_bytes).ok_or(CryptoError::VerificationFailed)?;
        if r.is_small_order() {
            return Err(CryptoError::VerificationFailed);
        }

        let mut s_bytes = [0_u8; 32];
        s_bytes.copy_from_slice(&signature.bytes[32..]);
        let s = Scalar::from_canonical_bytes(&s_bytes).ok_or(CryptoError::VerificationFailed)?;

        let mut hasher = Sha512::new();
        hasher.update(&r_bytes);
        hasher.update(&self.bytes);
        hasher.update(message);
        let k = Scalar::from_hash64(&hasher.finalize());

        let left = Point::BASE.scalar_mul(&s.to_bytes());
        let right = r.add(public.scalar_mul(&k.to_bytes()));
        if left.equals(right) {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

impl fmt::Debug for Ed25519PublicKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519PublicKey(")?;
        for byte in self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature {
    bytes: [u8; ED25519_SIGNATURE_BYTES],
}

impl Ed25519Signature {
    /// Creates a signature from exactly 64 bytes.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; ED25519_SIGNATURE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Parses a signature from a byte slice of exactly 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] for any other length.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let source = <[u8; ED25519_SIGNATURE_BYTES]>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self { bytes: source })
    }

    /// Returns the 64-byte encoding.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; ED25519_SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; ED25519_SIGNATURE_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for Ed25519Signature {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519Signature(")?;
        for byte in self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

fn expand(seed: &[u8; ED25519_SEED_BYTES]) -> ([u8; 32], Scalar, [u8; 32]) {
    let hash = sha512(seed);
    let mut scalar_bytes = [0_u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    scalar_bytes[0] &= 0xf8;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let scalar = Scalar::from_bytes_reduce(&scalar_bytes);
    let mut prefix = [0_u8; 32];
    prefix.copy_from_slice(&hash[32..]);
    (scalar_bytes, scalar, prefix)
}

#[cfg(test)]
mod tests {
    use super::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
    use qwp_core::CryptoError;

    fn hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write;
        let mut output = std::string::String::new();
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    fn bytes32(value: &str) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&value[start..start + 2], 16).unwrap();
        }
        output
    }

    fn bytes64(value: &str) -> [u8; 64] {
        let mut output = [0_u8; 64];
        for (index, byte) in output.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&value[start..start + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn rfc8032_vector_1() {
        let seed = bytes32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            bytes32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = bytes64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let private = Ed25519PrivateKey::from_seed(seed);
        let public = private.public_key();
        assert_eq!(public.to_bytes(), expected_public);
        let signature = private.sign(b"");
        assert_eq!(signature.to_bytes(), expected_signature);
        assert_eq!(public.verify(b"", &signature), Ok(()));
    }

    #[test]
    fn rfc8032_vector_2() {
        let seed = bytes32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_public =
            bytes32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let expected_signature = bytes64(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        let private = Ed25519PrivateKey::from_seed(seed);
        let public = private.public_key();
        assert_eq!(public.to_bytes(), expected_public);
        let signature = private.sign(&[0x72]);
        assert_eq!(signature.to_bytes(), expected_signature);
        assert_eq!(public.verify(&[0x72], &signature), Ok(()));
    }

    #[test]
    fn rejects_wrong_message_and_tampering() {
        let private = Ed25519PrivateKey::from_seed([7_u8; 32]);
        let public = private.public_key();
        let signature = private.sign(b"message");
        assert_eq!(
            public.verify(b"wrong", &signature),
            Err(CryptoError::VerificationFailed)
        );
        let mut bytes = signature.to_bytes();
        bytes[0] ^= 1;
        assert_eq!(
            public.verify(b"message", &Ed25519Signature::from_bytes(bytes)),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_non_canonical_s() {
        let private = Ed25519PrivateKey::from_seed([9_u8; 32]);
        let public = private.public_key();
        let signature = private.sign(b"message");
        let mut bytes = signature.to_bytes();
        for byte in &mut bytes[32..] {
            *byte = 0xff;
        }
        assert_eq!(
            public.verify(b"message", &Ed25519Signature::from_bytes(bytes)),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn accessors_and_signature_parsing() {
        let seed = [13_u8; 32];
        let private = Ed25519PrivateKey::from_seed(seed);
        assert_eq!(private.seed(), &seed);
        let debug = std::format!("{private:?}");
        assert!(debug.contains("Ed25519PrivateKey"));
        assert!(!debug.contains("seed"));
        let signature = private.sign(b"accessors");
        let signature_debug = std::format!("{signature:?}");
        assert!(signature_debug.starts_with("Ed25519Signature("));
        assert_eq!(
            Ed25519Signature::from_slice(signature.as_bytes()),
            Ok(signature)
        );
        assert!(Ed25519Signature::from_slice(&signature.as_bytes()[..63]).is_err());
    }

    #[test]
    fn rejects_invalid_public_keys_and_points() {
        assert!(Ed25519PublicKey::from_bytes(&[0_u8; 32]).is_err());
        assert!(Ed25519PublicKey::from_bytes(&[0xff_u8; 32]).is_err());
        let private = Ed25519PrivateKey::from_seed([15_u8; 32]);
        let public = private.public_key();
        let signature = private.sign(b"points");
        let mut identity_r = signature.to_bytes();
        identity_r[..32].fill(0);
        identity_r[0] = 1;
        identity_r[32..].fill(0);
        assert_eq!(
            public.verify(b"points", &Ed25519Signature::from_bytes(identity_r)),
            Err(CryptoError::VerificationFailed)
        );
        let mut invalid_r = signature.to_bytes();
        invalid_r[..32].fill(0xff);
        assert_eq!(
            public.verify(b"points", &Ed25519Signature::from_bytes(invalid_r)),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn public_key_round_trip() {
        let private = Ed25519PrivateKey::from_seed([11_u8; 32]);
        let public = private.public_key();
        let bytes = public.to_bytes();
        assert_eq!(Ed25519PublicKey::from_bytes(&bytes), Ok(public));
        let debug = std::format!("{public:?}");
        assert!(debug.starts_with("Ed25519PublicKey("));
        assert_eq!(hex(&bytes).len(), 64);
    }
}
