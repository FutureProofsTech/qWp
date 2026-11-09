//! QHS-6: QHS-5 + Ed25519 classical hybrid.
//!
//! Both components sign the same key-and-message transcript. Verification
//! accepts only if both signatures verify. The proof is in `docs/17-qhs6.md`.

use core::fmt;
use core::mem::size_of;

use qwp_classical::{
    ED25519_PUBLIC_KEY_BYTES, ED25519_SEED_BYTES, ED25519_SIGNATURE_BYTES, Ed25519PrivateKey,
    Ed25519PublicKey, Ed25519Signature,
};
use qwp_core::CryptoError;
use qwp_hash::DeriveKey64;

use crate::qhs5::{
    QHS5_LEAF_COUNT, QHS5_MAX_SIGNATURES, QHS5_PRIVATE_KEY_BYTES, QHS5_PUBLIC_KEY_BYTES,
    QHS5_SIGNATURE_BYTES, Qhs5PrivateKey, Qhs5PublicKey, Qhs5Signature,
};

/// Hybrid public-key size.
pub const QHS6_PUBLIC_KEY_BYTES: usize = 4 + QHS5_PUBLIC_KEY_BYTES + ED25519_PUBLIC_KEY_BYTES;
/// Hybrid private-key size.
pub const QHS6_PRIVATE_KEY_BYTES: usize = 4 + QHS5_PRIVATE_KEY_BYTES + ED25519_SEED_BYTES;
/// Hybrid signature size.
pub const QHS6_SIGNATURE_BYTES: usize = 4 + QHS5_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES;
/// Signatures available from one hybrid key.
pub const QHS6_MAX_SIGNATURES: u16 = QHS5_MAX_SIGNATURES;

const KEY_HEADER: [u8; 4] = [7, 7, 8, 0];
const QHS5_PUBLIC_OFFSET: usize = 4;
const ED25519_PUBLIC_OFFSET: usize = QHS5_PUBLIC_OFFSET + QHS5_PUBLIC_KEY_BYTES;
const QHS5_PRIVATE_OFFSET: usize = 4;
const ED25519_SEED_OFFSET: usize = QHS5_PRIVATE_OFFSET + QHS5_PRIVATE_KEY_BYTES;
const QHS5_SIGNATURE_OFFSET: usize = 4;
const ED25519_SIGNATURE_OFFSET: usize = QHS5_SIGNATURE_OFFSET + QHS5_SIGNATURE_BYTES;
const TRANSCRIPT_CONTEXT: &[u8] = b"qWp QHS-6 transcript";

/// A QHS-6 hybrid public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Qhs6PublicKey {
    bytes: [u8; QHS6_PUBLIC_KEY_BYTES],
}

impl Qhs6PublicKey {
    /// Builds a hybrid public key from its components.
    #[must_use]
    #[inline]
    pub fn from_parts(qhs5: Qhs5PublicKey, ed25519: Ed25519PublicKey) -> Self {
        let mut bytes = [0_u8; QHS6_PUBLIC_KEY_BYTES];
        bytes[..4].copy_from_slice(&KEY_HEADER);
        bytes[QHS5_PUBLIC_OFFSET..ED25519_PUBLIC_OFFSET].copy_from_slice(&qhs5.to_bytes());
        bytes[ED25519_PUBLIC_OFFSET..].copy_from_slice(&ed25519.to_bytes());
        Self { bytes }
    }

    /// Parses a hybrid public key from its exact 108-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported header or an invalid component.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS6_PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        if bytes.get(..4) != Some(KEY_HEADER.as_slice()) {
            return Err(CryptoError::InvalidLength);
        }
        let qhs5_bytes = <[u8; QHS5_PUBLIC_KEY_BYTES]>::try_from(
            bytes
                .get(QHS5_PUBLIC_OFFSET..ED25519_PUBLIC_OFFSET)
                .ok_or(CryptoError::InvalidLength)?,
        )
        .map_err(|_| CryptoError::InvalidLength)?;
        let _ = Qhs5PublicKey::from_bytes(&qhs5_bytes)?;
        let ed_bytes = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(
            bytes
                .get(ED25519_PUBLIC_OFFSET..)
                .ok_or(CryptoError::InvalidLength)?,
        )
        .map_err(|_| CryptoError::InvalidLength)?;
        let _ = Ed25519PublicKey::from_bytes(&ed_bytes)?;
        Ok(Self { bytes: *bytes })
    }

    /// Returns the exact 108-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS6_PUBLIC_KEY_BYTES] {
        self.bytes
    }

    /// Returns the QHS-5 component.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed layout is malformed.
    #[inline]
    pub fn qhs5_public_key(&self) -> Result<Qhs5PublicKey, CryptoError> {
        let bytes = <[u8; QHS5_PUBLIC_KEY_BYTES]>::try_from(
            self.bytes
                .get(QHS5_PUBLIC_OFFSET..ED25519_PUBLIC_OFFSET)
                .ok_or(CryptoError::InvalidLength)?,
        )
        .map_err(|_| CryptoError::InvalidLength)?;
        Qhs5PublicKey::from_bytes(&bytes)
    }

    /// Returns the Ed25519 component.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed layout is malformed.
    #[inline]
    pub fn ed25519_public_key(&self) -> Result<Ed25519PublicKey, CryptoError> {
        let bytes = <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(
            self.bytes
                .get(ED25519_PUBLIC_OFFSET..)
                .ok_or(CryptoError::InvalidLength)?,
        )
        .map_err(|_| CryptoError::InvalidLength)?;
        Ed25519PublicKey::from_bytes(&bytes)
    }

    /// Verifies a hybrid signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerificationFailed`] unless both components
    /// verify on the same transcript.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &Qhs6Signature) -> Result<(), CryptoError> {
        if signature.leaf_index()? != signature.qhs5_signature()?.leaf_index()? {
            return Err(CryptoError::VerificationFailed);
        }
        let qhs5_public = self.qhs5_public_key()?;
        let ed25519_public = self.ed25519_public_key()?;
        let transcript = transcript(&qhs5_public, &ed25519_public, message);
        qhs5_public.verify(&transcript, &signature.qhs5_signature()?)?;
        ed25519_public.verify(&transcript, &signature.ed25519_signature()?)?;
        Ok(())
    }
}

impl fmt::Debug for Qhs6PublicKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Qhs6PublicKey(")?;
        for byte in self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// A QHS-6 hybrid private key.
pub struct Qhs6PrivateKey {
    qhs5: Qhs5PrivateKey,
    ed25519: Ed25519PrivateKey,
}

impl Qhs6PrivateKey {
    /// Builds a hybrid private key from its components.
    #[must_use]
    #[inline]
    pub const fn from_parts(qhs5: Qhs5PrivateKey, ed25519: Ed25519PrivateKey) -> Self {
        Self { qhs5, ed25519 }
    }

    /// Parses a hybrid private key from its exact 108-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported header or an invalid component.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS6_PRIVATE_KEY_BYTES]) -> Result<Self, CryptoError> {
        if bytes.get(..4) != Some(KEY_HEADER.as_slice()) {
            return Err(CryptoError::InvalidLength);
        }
        let qhs5_bytes = <[u8; QHS5_PRIVATE_KEY_BYTES]>::try_from(
            bytes
                .get(QHS5_PRIVATE_OFFSET..ED25519_SEED_OFFSET)
                .ok_or(CryptoError::InvalidLength)?,
        )
        .map_err(|_| CryptoError::InvalidLength)?;
        let qhs5 = Qhs5PrivateKey::from_bytes(&qhs5_bytes)?;
        let ed_bytes = <[u8; ED25519_SEED_BYTES]>::try_from(
            bytes
                .get(ED25519_SEED_OFFSET..)
                .ok_or(CryptoError::InvalidLength)?,
        )
        .map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self {
            qhs5,
            ed25519: Ed25519PrivateKey::from_seed(ed_bytes),
        })
    }

    /// Returns the exact 108-byte representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; QHS6_PRIVATE_KEY_BYTES] {
        let mut bytes = [0_u8; QHS6_PRIVATE_KEY_BYTES];
        bytes[..4].copy_from_slice(&KEY_HEADER);
        bytes[QHS5_PRIVATE_OFFSET..ED25519_SEED_OFFSET].copy_from_slice(&self.qhs5.to_bytes());
        bytes[ED25519_SEED_OFFSET..].copy_from_slice(self.ed25519.seed());
        bytes
    }

    /// Returns the QHS-5 seed.
    #[must_use]
    #[inline]
    pub const fn qhs5_seed(&self) -> &[u8; 64] {
        self.qhs5.seed()
    }

    /// Returns the next QHS-5 leaf index.
    #[must_use]
    #[inline]
    pub const fn next_leaf(&self) -> u16 {
        self.qhs5.next_leaf()
    }

    /// Returns `true` when no signatures remain.
    #[must_use]
    #[inline]
    pub const fn is_exhausted(&self) -> bool {
        self.qhs5.is_exhausted()
    }

    /// Signs a message and consumes one QHS-5 leaf.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 256 signatures.
    #[inline]
    pub fn sign(&mut self, message: &[u8]) -> Result<Qhs6Signature, CryptoError> {
        let leaves = crate::qhs5::qhs5_leaves(self.qhs5.seed())?;
        self.sign_with_leaves(message, &leaves)
    }

    /// Signs a message using precomputed QHS-5 leaves.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 256 signatures.
    #[inline]
    pub fn sign_with_leaves(
        &mut self,
        message: &[u8],
        leaves: &[[u8; 64]; QHS5_LEAF_COUNT],
    ) -> Result<Qhs6Signature, CryptoError> {
        if self.is_exhausted() {
            return Err(CryptoError::KeyExhausted);
        }
        let (_, qhs5_public) = crate::qhs5::qhs5_keygen_from_leaves(self.qhs5.seed(), leaves)?;
        let ed25519_public = self.ed25519.public_key();
        let transcript = transcript(&qhs5_public, &ed25519_public, message);
        let qhs5_signature = self.qhs5.sign_with_leaves(&transcript, leaves)?;
        let ed25519_signature = self.ed25519.sign(&transcript);
        Qhs6Signature::from_parts(
            qhs5_signature.leaf_index()?,
            qhs5_signature,
            ed25519_signature,
        )
    }
}

impl fmt::Debug for Qhs6PrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Qhs6PrivateKey")
            .field("next_leaf", &self.next_leaf())
            .finish_non_exhaustive()
    }
}

/// A QHS-6 hybrid signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Qhs6Signature {
    bytes: [u8; QHS6_SIGNATURE_BYTES],
}

impl Qhs6Signature {
    /// Builds a hybrid signature from its components.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf indices disagree.
    #[inline]
    pub fn from_parts(
        leaf_index: u16,
        qhs5: Qhs5Signature,
        ed25519: Ed25519Signature,
    ) -> Result<Self, CryptoError> {
        if qhs5.leaf_index()? != leaf_index {
            return Err(CryptoError::InvalidLength);
        }
        let mut bytes = [0_u8; QHS6_SIGNATURE_BYTES];
        bytes[..4].copy_from_slice(&[7, 7, 0, 0]);
        bytes[2..4].copy_from_slice(&leaf_index.to_le_bytes());
        bytes[QHS5_SIGNATURE_OFFSET..ED25519_SIGNATURE_OFFSET].copy_from_slice(&qhs5.to_bytes());
        bytes[ED25519_SIGNATURE_OFFSET..].copy_from_slice(&ed25519.to_bytes());
        Ok(Self { bytes })
    }

    /// Parses a hybrid signature from exactly 6,284 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported header or malformed component.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let source = <[u8; QHS6_SIGNATURE_BYTES]>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidLength)?;
        if source.get(..2) != Some([7, 7].as_slice()) {
            return Err(CryptoError::InvalidLength);
        }
        let mut leaf = [0_u8; 2];
        leaf.copy_from_slice(source.get(2..4).ok_or(CryptoError::InvalidLength)?);
        if u16::from_le_bytes(leaf) >= QHS6_MAX_SIGNATURES {
            return Err(CryptoError::InvalidLength);
        }
        let qhs5 = Qhs5Signature::from_slice(
            source
                .get(QHS5_SIGNATURE_OFFSET..ED25519_SIGNATURE_OFFSET)
                .ok_or(CryptoError::InvalidLength)?,
        )?;
        let ed25519 = Ed25519Signature::from_slice(
            source
                .get(ED25519_SIGNATURE_OFFSET..)
                .ok_or(CryptoError::InvalidLength)?,
        )?;
        let signature = Self { bytes: source };
        if signature.leaf_index()? != qhs5.leaf_index()? {
            return Err(CryptoError::InvalidLength);
        }
        if signature.ed25519_signature()? != ed25519 {
            return Err(CryptoError::InvalidLength);
        }
        Ok(signature)
    }

    /// Returns the exact 6,284-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS6_SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; QHS6_SIGNATURE_BYTES] {
        &self.bytes
    }

    /// Returns the hybrid leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed layout is malformed.
    #[inline]
    pub fn leaf_index(&self) -> Result<u16, CryptoError> {
        let mut leaf = [0_u8; 2];
        leaf.copy_from_slice(self.bytes.get(2..4).ok_or(CryptoError::InvalidLength)?);
        Ok(u16::from_le_bytes(leaf))
    }

    /// Returns the QHS-5 component.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed layout is malformed.
    #[inline]
    pub fn qhs5_signature(&self) -> Result<Qhs5Signature, CryptoError> {
        Qhs5Signature::from_slice(
            self.bytes
                .get(QHS5_SIGNATURE_OFFSET..ED25519_SIGNATURE_OFFSET)
                .ok_or(CryptoError::InvalidLength)?,
        )
    }

    /// Returns the Ed25519 component.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed layout is malformed.
    #[inline]
    pub fn ed25519_signature(&self) -> Result<Ed25519Signature, CryptoError> {
        Ed25519Signature::from_slice(
            self.bytes
                .get(ED25519_SIGNATURE_OFFSET..)
                .ok_or(CryptoError::InvalidLength)?,
        )
    }
}

impl fmt::Debug for Qhs6Signature {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Qhs6Signature(")?;
        for byte in self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

fn transcript(qhs5: &Qhs5PublicKey, ed25519: &Ed25519PublicKey, message: &[u8]) -> [u8; 64] {
    let mut hasher = DeriveKey64::new(TRANSCRIPT_CONTEXT).hasher();
    hasher.update(&qhs5.to_bytes());
    hasher.update(&ed25519.to_bytes());
    hasher.update(message);
    hasher.finalize().to_bytes()
}

/// Generates a QHS-6 hybrid key pair.
///
/// # Errors
///
/// Returns an internal length error if a fixed-size buffer is malformed.
#[inline]
pub fn qhs6_keygen(
    qhs5_seed: &[u8; 64],
    ed25519_seed: &[u8; ED25519_SEED_BYTES],
) -> Result<(Qhs6PrivateKey, Qhs6PublicKey), CryptoError> {
    let (qhs5_private, qhs5_public) = crate::qhs5::keygen(qhs5_seed)?;
    let ed25519_private = Ed25519PrivateKey::from_seed(*ed25519_seed);
    let ed25519_public = ed25519_private.public_key();
    Ok((
        Qhs6PrivateKey::from_parts(qhs5_private, ed25519_private),
        Qhs6PublicKey::from_parts(qhs5_public, ed25519_public),
    ))
}

/// Generates a QHS-6 hybrid key pair from precomputed QHS-5 leaves.
///
/// # Errors
///
/// Returns an internal length error if a fixed-size buffer is malformed.
#[inline]
pub fn qhs6_keygen_from_leaves(
    qhs5_seed: &[u8; 64],
    ed25519_seed: &[u8; ED25519_SEED_BYTES],
    leaves: &[[u8; 64]; QHS5_LEAF_COUNT],
) -> Result<(Qhs6PrivateKey, Qhs6PublicKey), CryptoError> {
    let (qhs5_private, qhs5_public) = crate::qhs5::qhs5_keygen_from_leaves(qhs5_seed, leaves)?;
    let ed25519_private = Ed25519PrivateKey::from_seed(*ed25519_seed);
    let ed25519_public = ed25519_private.public_key();
    Ok((
        Qhs6PrivateKey::from_parts(qhs5_private, ed25519_private),
        Qhs6PublicKey::from_parts(qhs5_public, ed25519_public),
    ))
}

const _: [(); QHS6_PUBLIC_KEY_BYTES] = [(); size_of::<Qhs6PublicKey>()];
const _: [(); QHS6_PRIVATE_KEY_BYTES - 4] = [(); size_of::<Qhs6PrivateKey>()];
const _: [(); QHS6_SIGNATURE_BYTES] = [(); size_of::<Qhs6Signature>()];
const _: [(); 6284] = [(); QHS6_SIGNATURE_BYTES];

#[cfg(test)]
mod tests {
    use super::{
        QHS6_PRIVATE_KEY_BYTES, QHS6_PUBLIC_KEY_BYTES, QHS6_SIGNATURE_BYTES, Qhs6PrivateKey,
        Qhs6PublicKey, Qhs6Signature, qhs6_keygen, qhs6_keygen_from_leaves,
    };
    use crate::qhs5::qhs5_leaves;
    use qwp_core::CryptoError;
    use qwp_hash::hash32;

    const QHS5_SEED: [u8; 64] = [7_u8; 64];
    const ED_SEED: [u8; 32] = [9_u8; 32];

    #[test]
    fn sign_verify_round_trip() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let signature = private_key.sign(b"qWp QHS-6 hybrid").unwrap();
        assert_eq!(public_key.verify(b"qWp QHS-6 hybrid", &signature), Ok(()));
        assert_eq!(signature.leaf_index(), Ok(0));
        assert_eq!(private_key.next_leaf(), 1);
        assert_eq!(
            public_key.verify(b"qWp QHS-6 wrong", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn transcript_binding_rejects_mixed_components() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let first = private_key.sign(b"first").unwrap();
        let second = private_key.sign(b"second").unwrap();
        let mixed_ed = Qhs6Signature::from_parts(
            first.leaf_index().unwrap(),
            first.qhs5_signature().unwrap(),
            second.ed25519_signature().unwrap(),
        )
        .unwrap();
        assert_eq!(
            public_key.verify(b"first", &mixed_ed),
            Err(CryptoError::VerificationFailed)
        );
        let mixed_qhs5 = Qhs6Signature::from_parts(
            first.leaf_index().unwrap(),
            second.qhs5_signature().unwrap(),
            first.ed25519_signature().unwrap(),
        );
        assert!(mixed_qhs5.is_err());
    }

    #[test]
    fn headers_and_sizes_are_exact() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        assert_eq!(QHS6_PUBLIC_KEY_BYTES, 108);
        assert_eq!(QHS6_PRIVATE_KEY_BYTES, 108);
        assert_eq!(QHS6_SIGNATURE_BYTES, 6_284);
        assert_eq!(&public_key.to_bytes()[..4], &[7, 7, 8, 0]);
        assert_eq!(&private_key.to_bytes()[..4], &[7, 7, 8, 0]);
        let signature = private_key.sign(b"header").unwrap();
        assert_eq!(&signature.to_bytes()[..4], &[7, 7, 0, 0]);
    }

    #[test]
    fn key_and_signature_round_trip() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let public_bytes = public_key.to_bytes();
        assert_eq!(Qhs6PublicKey::from_bytes(&public_bytes), Ok(public_key));
        let private_bytes = private_key.to_bytes();
        let parsed = Qhs6PrivateKey::from_bytes(&private_bytes).unwrap();
        assert_eq!(parsed.qhs5_seed(), private_key.qhs5_seed());
        assert_eq!(parsed.next_leaf(), private_key.next_leaf());
        let signature = private_key.sign(b"round-trip").unwrap();
        let signature_bytes = signature.to_bytes();
        assert_eq!(Qhs6Signature::from_slice(&signature_bytes), Ok(signature));
        assert_eq!(public_key.verify(b"round-trip", &signature), Ok(()));
    }

    #[test]
    fn cached_leaves_match_sequential() {
        let leaves = qhs5_leaves(&QHS5_SEED).unwrap();
        let (mut sequential, sequential_public) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let (mut cached, cached_public) =
            qhs6_keygen_from_leaves(&QHS5_SEED, &ED_SEED, &leaves).unwrap();
        assert_eq!(sequential_public, cached_public);
        let first = sequential.sign(b"cached").unwrap();
        let second = cached.sign_with_leaves(b"cached", &leaves).unwrap();
        assert_eq!(first, second);
        assert_eq!(cached_public.verify(b"cached", &second), Ok(()));
    }

    #[test]
    fn rejects_tampering_and_wrong_key() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let signature = private_key.sign(b"tamper").unwrap();
        let mut tampered = signature.to_bytes();
        tampered[100] ^= 1;
        assert_eq!(
            public_key.verify(b"tamper", &Qhs6Signature::from_slice(&tampered).unwrap()),
            Err(CryptoError::VerificationFailed)
        );
        let mut tampered_ed = signature.to_bytes();
        tampered_ed[6_250] ^= 1;
        assert_eq!(
            public_key.verify(b"tamper", &Qhs6Signature::from_slice(&tampered_ed).unwrap()),
            Err(CryptoError::VerificationFailed)
        );
        let (_, other_public) = qhs6_keygen(&[11_u8; 64], &[12_u8; 32]).unwrap();
        assert_eq!(
            other_public.verify(b"tamper", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_exhausted_key() {
        let (private_key, _public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let mut bytes = private_key.to_bytes();
        bytes[72..74].copy_from_slice(&256_u16.to_le_bytes());
        let mut exhausted = Qhs6PrivateKey::from_bytes(&bytes).unwrap();
        assert!(exhausted.is_exhausted());
        assert_eq!(exhausted.sign(b"message"), Err(CryptoError::KeyExhausted));
    }

    #[test]
    fn rejects_bad_headers() {
        let (_, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let mut bytes = public_key.to_bytes();
        bytes[0] = 0;
        assert!(Qhs6PublicKey::from_bytes(&bytes).is_err());
        bytes[0] = 7;
        bytes[3] = 1;
        assert!(Qhs6PublicKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn debug_and_as_bytes() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let signature = private_key.sign(b"debug").unwrap();
        let public_debug = std::format!("{public_key:?}");
        assert!(public_debug.starts_with("Qhs6PublicKey("));
        let private_debug = std::format!("{private_key:?}");
        assert!(private_debug.contains("Qhs6PrivateKey"));
        assert!(!private_debug.contains("seed"));
        let signature_debug = std::format!("{signature:?}");
        assert!(signature_debug.starts_with("Qhs6Signature("));
        assert_eq!(signature.as_bytes(), &signature.to_bytes());
    }

    #[test]
    fn parser_error_paths() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let signature = private_key.sign(b"errors").unwrap();

        let mut bad_public = public_key.to_bytes();
        bad_public[0] = 0;
        assert!(Qhs6PublicKey::from_bytes(&bad_public).is_err());
        bad_public = public_key.to_bytes();
        bad_public[4] = 0;
        assert!(Qhs6PublicKey::from_bytes(&bad_public).is_err());
        bad_public = public_key.to_bytes();
        bad_public[76..108].fill(0);
        assert!(Qhs6PublicKey::from_bytes(&bad_public).is_err());

        let mut bad_private = private_key.to_bytes();
        bad_private[0] = 0;
        assert!(Qhs6PrivateKey::from_bytes(&bad_private).is_err());
        bad_private = private_key.to_bytes();
        bad_private[4] = 0;
        assert!(Qhs6PrivateKey::from_bytes(&bad_private).is_err());

        let mut bad_signature = signature.to_bytes();
        bad_signature[0] = 0;
        assert!(Qhs6Signature::from_slice(&bad_signature).is_err());
        bad_signature = signature.to_bytes();
        bad_signature[2..4].copy_from_slice(&256_u16.to_le_bytes());
        assert!(Qhs6Signature::from_slice(&bad_signature).is_err());
        assert!(
            Qhs6Signature::from_parts(
                1,
                signature.qhs5_signature().unwrap(),
                signature.ed25519_signature().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn counter_and_leaf_index_accessors() {
        let (mut private_key, _public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        assert_eq!(private_key.next_leaf(), 0);
        assert!(!private_key.is_exhausted());
        let first = private_key.sign(b"first").unwrap();
        assert_eq!(first.leaf_index(), Ok(0));
        assert_eq!(private_key.next_leaf(), 1);
        let second = private_key.sign(b"second").unwrap();
        assert_eq!(second.leaf_index(), Ok(1));
        assert_eq!(private_key.next_leaf(), 2);
    }

    #[test]
    fn rejects_leaf_mismatch() {
        let (mut private_key, public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let signature = private_key.sign(b"leaf mismatch").unwrap();
        let mut bytes = signature.to_bytes();
        bytes[6..8].copy_from_slice(&1_u16.to_le_bytes());
        assert!(Qhs6Signature::from_slice(&bytes).is_err());
        bytes = signature.to_bytes();
        bytes[2..4].copy_from_slice(&1_u16.to_le_bytes());
        let forced = Qhs6Signature { bytes };
        assert_eq!(
            public_key.verify(b"leaf mismatch", &forced),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn known_answer_signature_hash() {
        let (mut private_key, _public_key) = qhs6_keygen(&QHS5_SEED, &ED_SEED).unwrap();
        let signature = private_key.sign(b"qWp QHS-6 KAT").unwrap();
        assert_eq!(
            std::format!("{:?}", hash32(&signature.to_bytes())),
            "Hash32(b93cdeb0897a04dc584bd744cbfa25329124d85479c5bead28a0aa471e971974)"
        );
    }
}
