//! QHS-1: qWp's custom hash-based signature.
//!
//! QHS-1 is a stateful Winternitz one-time signature (WOTS) with a Merkle
//! authentication tree. It is built only on the in-tree BLAKE3 implementation.
//! The security proof is in `docs/05-qhs1.md`.

use core::fmt;
use core::mem::size_of;

use qwp_core::CryptoError;
use qwp_hash::{Hasher, derive_key32};

/// Number of WOTS hash chains.
const WOTS_CHAINS: usize = 67;
/// Maximum WOTS chain steps.
const WOTS_CHAIN_LEN: u8 = 15;
/// Bytes in the WOTS signature.
const WOTS_SIGNATURE_BYTES: usize = WOTS_CHAINS * 32;
/// Merkle tree height.
const TREE_HEIGHT: usize = 8;
/// Number of Merkle leaves.
const LEAF_COUNT: usize = 256;
/// Bytes in a Merkle authentication path.
const AUTH_PATH_BYTES: usize = TREE_HEIGHT * 32;
/// Signature header bytes (version, algorithm, leaf index).
const SIGNATURE_HEADER_BYTES: usize = 4;
/// Signature checksum bytes.
const SIGNATURE_CHECKSUM_BYTES: usize = 4;
/// Offset of the WOTS signature.
const WOTS_OFFSET: usize = SIGNATURE_HEADER_BYTES;
/// Offset of the authentication path.
const AUTH_OFFSET: usize = WOTS_OFFSET + WOTS_SIGNATURE_BYTES;
/// Offset of the checksum.
const CHECKSUM_OFFSET: usize = AUTH_OFFSET + AUTH_PATH_BYTES;
/// Bytes covered by the checksum.
const CHECKSUM_BODY_BYTES: usize = CHECKSUM_OFFSET;

/// Public key size in bytes.
pub const QHS_PUBLIC_KEY_BYTES: usize = 64;
/// Private key size in bytes.
pub const QHS_PRIVATE_KEY_BYTES: usize = 64;
/// Signature size in bytes.
pub const QHS_SIGNATURE_BYTES: usize = CHECKSUM_OFFSET + SIGNATURE_CHECKSUM_BYTES;
/// Number of signatures available from one private key.
pub const QHS_MAX_SIGNATURES: u16 = 256;

const SECRET_CONTEXT: &[u8] = b"qWp QHS-1 secret";
const CHAIN_CONTEXT: &[u8] = b"qWp QHS-1 chain";
const WOTS_PK_CONTEXT: &[u8] = b"qWp QHS-1 wots-pk";
const LEAF_CONTEXT: &[u8] = b"qWp QHS-1 leaf";
const NODE_CONTEXT: &[u8] = b"qWp QHS-1 node";
const MESSAGE_CONTEXT: &[u8] = b"qWp QHS-1 message";
const CHECKSUM_CONTEXT: &[u8] = b"qWp QHS-1 signature-checksum";

/// A QHS-1 public key: a Merkle root and algorithm metadata.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QhsPublicKey {
    bytes: [u8; QHS_PUBLIC_KEY_BYTES],
}

impl QhsPublicKey {
    /// Creates a public key from a Merkle root.
    #[must_use]
    #[inline]
    pub fn from_root(root: [u8; 32]) -> Self {
        let mut bytes = [0_u8; QHS_PUBLIC_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..4) {
            slot.copy_from_slice(&[1, 1, u8::try_from(TREE_HEIGHT).unwrap_or(0), 0]);
        }
        if let Some(slot) = bytes.get_mut(4..36) {
            slot.copy_from_slice(&root);
        }
        Self { bytes }
    }

    /// Parses a public key from its exact 64-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, algorithm, height, or
    /// non-zero reserved bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS_PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        let version = bytes.first().copied().ok_or(CryptoError::InvalidLength)?;
        let algorithm = bytes.get(1).copied().ok_or(CryptoError::InvalidLength)?;
        let height = bytes.get(2).copied().ok_or(CryptoError::InvalidLength)?;
        let reserved = bytes.get(3).copied().ok_or(CryptoError::InvalidLength)?;
        if version != 1
            || algorithm != 1
            || height != u8::try_from(TREE_HEIGHT).unwrap_or(0)
            || reserved != 0
        {
            return Err(CryptoError::InvalidLength);
        }
        let mut output = [0_u8; QHS_PUBLIC_KEY_BYTES];
        output.copy_from_slice(bytes);
        Ok(Self { bytes: output })
    }

    /// Returns the exact 64-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS_PUBLIC_KEY_BYTES] {
        self.bytes
    }

    /// Returns the Merkle root.
    #[must_use]
    #[inline]
    pub fn root(&self) -> [u8; 32] {
        let mut root = [0_u8; 32];
        if let Some(slot) = self.bytes.get(4..36) {
            root.copy_from_slice(slot);
        }
        root
    }

    /// Verifies a QHS-1 signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerificationFailed`] for an invalid signature.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &QhsSignature) -> Result<(), CryptoError> {
        let bytes = signature.as_bytes();
        if bytes.first() != Some(&1) || bytes.get(1) != Some(&1) {
            return Err(CryptoError::VerificationFailed);
        }
        let leaf_bytes = bytes.get(2..4).ok_or(CryptoError::VerificationFailed)?;
        let mut leaf_word = [0_u8; 2];
        leaf_word.copy_from_slice(leaf_bytes);
        let leaf_index = u16::from_le_bytes(leaf_word);
        if leaf_index >= QHS_MAX_SIGNATURES {
            return Err(CryptoError::VerificationFailed);
        }

        let body = bytes
            .get(..CHECKSUM_BODY_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let expected_checksum = signature_checksum(body)?;
        let actual_checksum = bytes
            .get(CHECKSUM_OFFSET..QHS_SIGNATURE_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        if actual_checksum != expected_checksum {
            return Err(CryptoError::VerificationFailed);
        }

        let digits = message_digits(message);
        let wots_signature = bytes
            .get(WOTS_OFFSET..AUTH_OFFSET)
            .ok_or(CryptoError::VerificationFailed)?;
        let wots_pk_hash = wots_verify(wots_signature, &digits)?;
        let mut node = leaf_hash(leaf_index, &wots_pk_hash);
        let auth_path = bytes
            .get(AUTH_OFFSET..CHECKSUM_OFFSET)
            .ok_or(CryptoError::VerificationFailed)?;

        for (level, sibling) in auth_path.as_chunks::<32>().0.iter().enumerate() {
            let level_u32 = u32::try_from(level).unwrap_or(0);
            let bit = leaf_index.checked_shr(level_u32).unwrap_or(0) & 1;
            if bit == 0 {
                node = node_hash(&node, sibling);
            } else {
                node = node_hash(sibling, &node);
            }
        }

        if node == self.root() {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// A QHS-1 private key.
///
/// The key is stateful: each signature consumes one Merkle leaf. It is not
/// `Clone`, is not printable, and is wiped best-effort on drop.
pub struct QhsPrivateKey {
    seed: [u8; 32],
    next_leaf: u16,
    reserved: [u8; 30],
}

impl QhsPrivateKey {
    /// Creates a private key from a seed and a starting leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if `next_leaf` exceeds [`QHS_MAX_SIGNATURES`].
    #[inline]
    pub const fn from_parts(seed: [u8; 32], next_leaf: u16) -> Result<Self, CryptoError> {
        if next_leaf > QHS_MAX_SIGNATURES {
            return Err(CryptoError::InvalidLength);
        }
        Ok(Self {
            seed,
            next_leaf,
            reserved: [0; 30],
        })
    }

    /// Parses a private key from its exact 64-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata or an out-of-range leaf counter.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS_PRIVATE_KEY_BYTES]) -> Result<Self, CryptoError> {
        let version = bytes.first().copied().ok_or(CryptoError::InvalidLength)?;
        let algorithm = bytes.get(1).copied().ok_or(CryptoError::InvalidLength)?;
        let height = bytes.get(2).copied().ok_or(CryptoError::InvalidLength)?;
        let reserved = bytes.get(3).copied().ok_or(CryptoError::InvalidLength)?;
        if version != 1
            || algorithm != 1
            || height != u8::try_from(TREE_HEIGHT).unwrap_or(0)
            || reserved != 0
        {
            return Err(CryptoError::InvalidLength);
        }
        let seed_slice = bytes.get(4..36).ok_or(CryptoError::InvalidLength)?;
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(seed_slice);
        let counter_slice = bytes.get(36..38).ok_or(CryptoError::InvalidLength)?;
        let mut counter_word = [0_u8; 2];
        counter_word.copy_from_slice(counter_slice);
        let next_leaf = u16::from_le_bytes(counter_word);
        let reserved_tail = bytes.get(38..64).ok_or(CryptoError::InvalidLength)?;
        if reserved_tail.iter().any(|byte| *byte != 0) {
            return Err(CryptoError::InvalidPadding);
        }
        Self::from_parts(seed, next_leaf)
    }

    /// Serializes the private key into its exact 64-byte representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; QHS_PRIVATE_KEY_BYTES] {
        let mut bytes = [0_u8; QHS_PRIVATE_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..4) {
            slot.copy_from_slice(&[1, 1, u8::try_from(TREE_HEIGHT).unwrap_or(0), 0]);
        }
        if let Some(slot) = bytes.get_mut(4..36) {
            slot.copy_from_slice(&self.seed);
        }
        if let Some(slot) = bytes.get_mut(36..38) {
            slot.copy_from_slice(&self.next_leaf.to_le_bytes());
        }
        if let (Some(slot), Some(source)) = (bytes.get_mut(38..64), self.reserved.get(..26)) {
            slot.copy_from_slice(source);
        }
        bytes
    }

    /// Returns the next leaf index.
    #[must_use]
    #[inline]
    pub const fn next_leaf(&self) -> u16 {
        self.next_leaf
    }

    /// Returns `true` when no signatures remain.
    #[must_use]
    #[inline]
    pub const fn is_exhausted(&self) -> bool {
        self.next_leaf >= QHS_MAX_SIGNATURES
    }

    /// Signs a message and consumes one Merkle leaf.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 256 signatures.
    #[inline]
    pub fn sign(&mut self, message: &[u8]) -> Result<QhsSignature, CryptoError> {
        if self.is_exhausted() {
            return Err(CryptoError::KeyExhausted);
        }
        let leaf_index = self.next_leaf;
        self.next_leaf = self.next_leaf.saturating_add(1);

        let digits = message_digits(message);
        let wots_signature = wots_sign(&self.seed, leaf_index, &digits)?;
        let auth_path = auth_path(&self.seed, leaf_index)?;
        let mut bytes = [0_u8; QHS_SIGNATURE_BYTES];

        if let Some(slot) = bytes.get_mut(0..4) {
            slot.copy_from_slice(&[1, 1, 0, 0]);
        }
        if let Some(slot) = bytes.get_mut(2..4) {
            slot.copy_from_slice(&leaf_index.to_le_bytes());
        }
        if let Some(slot) = bytes.get_mut(WOTS_OFFSET..AUTH_OFFSET) {
            slot.copy_from_slice(&wots_signature);
        }
        if let Some(slot) = bytes.get_mut(AUTH_OFFSET..CHECKSUM_OFFSET) {
            for (destination, source) in slot
                .as_chunks_mut::<32>()
                .0
                .iter_mut()
                .zip(auth_path.iter())
            {
                destination.copy_from_slice(source);
            }
        }
        let body = bytes
            .get(..CHECKSUM_BODY_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        let checksum = signature_checksum(body)?;
        if let Some(slot) = bytes.get_mut(CHECKSUM_OFFSET..QHS_SIGNATURE_BYTES) {
            slot.copy_from_slice(&checksum);
        }

        Ok(QhsSignature { bytes })
    }
}

impl Drop for QhsPrivateKey {
    #[inline]
    fn drop(&mut self) {
        self.seed.fill(0);
        self.next_leaf = 0;
    }
}

impl fmt::Debug for QhsPrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QhsPrivateKey")
            .field("next_leaf", &self.next_leaf)
            .finish_non_exhaustive()
    }
}

/// A QHS-1 signature.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QhsSignature {
    bytes: [u8; QHS_SIGNATURE_BYTES],
}

impl QhsSignature {
    /// Creates a signature from its exact 2408-byte representation.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; QHS_SIGNATURE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Returns the exact 2408-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS_SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; QHS_SIGNATURE_BYTES] {
        &self.bytes
    }

    /// Returns the leaf index carried by the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is too short.
    #[inline]
    pub fn leaf_index(&self) -> Result<u16, CryptoError> {
        let bytes = self.bytes.get(2..4).ok_or(CryptoError::InvalidLength)?;
        let mut word = [0_u8; 2];
        word.copy_from_slice(bytes);
        Ok(u16::from_le_bytes(word))
    }
}

/// Generates a QHS-1 key pair from a 32-byte seed.
///
/// # Errors
///
/// Returns an internal length error if a fixed-size buffer is malformed.
#[inline]
pub fn keygen(seed: &[u8; 32]) -> Result<(QhsPrivateKey, QhsPublicKey), CryptoError> {
    let leaves = compute_leaves(seed)?;
    let root = merkle_root(leaves)?;
    let private_key = QhsPrivateKey::from_parts(*seed, 0)?;
    let public_key = QhsPublicKey::from_root(root);
    Ok((private_key, public_key))
}

fn secret(seed: &[u8; 32], leaf_index: u16, chain_index: u8) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(SECRET_CONTEXT);
    hasher.update(seed);
    hasher.update(&leaf_index.to_le_bytes());
    hasher.update(&[chain_index]);
    hasher.finalize().to_bytes()
}

fn chain_hash(value: &[u8; 32]) -> [u8; 32] {
    derive_key32(CHAIN_CONTEXT, value).to_bytes()
}

fn wots_pk_hash(seed: &[u8; 32], leaf_index: u16) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(WOTS_PK_CONTEXT);
    for chain_index in 0..WOTS_CHAINS {
        let chain_u8 = u8::try_from(chain_index).unwrap_or(0);
        let mut value = secret(seed, leaf_index, chain_u8);
        for _ in 0..WOTS_CHAIN_LEN {
            value = chain_hash(&value);
        }
        hasher.update(&value);
    }
    hasher.finalize().to_bytes()
}

fn leaf_hash(leaf_index: u16, wots_pk: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 34];
    if let Some(slot) = input.get_mut(0..2) {
        slot.copy_from_slice(&leaf_index.to_le_bytes());
    }
    if let Some(slot) = input.get_mut(2..34) {
        slot.copy_from_slice(wots_pk);
    }
    derive_key32(LEAF_CONTEXT, &input).to_bytes()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 64];
    if let Some(slot) = input.get_mut(0..32) {
        slot.copy_from_slice(left);
    }
    if let Some(slot) = input.get_mut(32..64) {
        slot.copy_from_slice(right);
    }
    derive_key32(NODE_CONTEXT, &input).to_bytes()
}

fn compute_leaves(seed: &[u8; 32]) -> Result<[[u8; 32]; LEAF_COUNT], CryptoError> {
    let mut leaves = [[0_u8; 32]; LEAF_COUNT];
    for (index, slot) in leaves.iter_mut().enumerate() {
        let leaf_index = u16::try_from(index).map_err(|_| CryptoError::InvalidLength)?;
        let wots_pk = wots_pk_hash(seed, leaf_index);
        *slot = leaf_hash(leaf_index, &wots_pk);
    }
    Ok(leaves)
}

fn merkle_root(mut nodes: [[u8; 32]; LEAF_COUNT]) -> Result<[u8; 32], CryptoError> {
    let mut count = LEAF_COUNT;
    while count > 1 {
        let half = count.checked_shr(1).unwrap_or(0);
        for index in 0..half {
            let left_index = index.checked_mul(2).unwrap_or(0);
            let right_index = left_index.checked_add(1).unwrap_or(0);
            let left = *nodes.get(left_index).ok_or(CryptoError::InvalidLength)?;
            let right = *nodes.get(right_index).ok_or(CryptoError::InvalidLength)?;
            let parent = node_hash(&left, &right);
            if let Some(slot) = nodes.get_mut(index) {
                *slot = parent;
            }
        }
        count = half;
    }
    nodes.first().copied().ok_or(CryptoError::InvalidLength)
}

fn auth_path(seed: &[u8; 32], leaf_index: u16) -> Result<[[u8; 32]; TREE_HEIGHT], CryptoError> {
    let mut nodes = compute_leaves(seed)?;
    let mut path = [[0_u8; 32]; TREE_HEIGHT];
    let mut count = LEAF_COUNT;

    for level in 0..TREE_HEIGHT {
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let sibling_index = usize::from(leaf_index).checked_shr(level_u32).unwrap_or(0) ^ 1;
        let sibling = *nodes.get(sibling_index).ok_or(CryptoError::InvalidLength)?;
        if let Some(slot) = path.get_mut(level) {
            *slot = sibling;
        }

        let half = count.checked_shr(1).unwrap_or(0);
        for index in 0..half {
            let left_index = index.checked_mul(2).unwrap_or(0);
            let right_index = left_index.checked_add(1).unwrap_or(0);
            let left = *nodes.get(left_index).ok_or(CryptoError::InvalidLength)?;
            let right = *nodes.get(right_index).ok_or(CryptoError::InvalidLength)?;
            let parent = node_hash(&left, &right);
            if let Some(slot) = nodes.get_mut(index) {
                *slot = parent;
            }
        }
        count = half;
    }

    Ok(path)
}

fn message_digits(message: &[u8]) -> [u8; WOTS_CHAINS] {
    let digest = derive_key32(MESSAGE_CONTEXT, message).to_bytes();
    let mut digits = [0_u8; WOTS_CHAINS];
    for (index, byte) in digest.iter().enumerate() {
        let high_index = index.checked_mul(2).unwrap_or(0);
        let low_index = high_index.checked_add(1).unwrap_or(0);
        if let Some(slot) = digits.get_mut(high_index) {
            *slot = byte.wrapping_shr(4);
        }
        if let Some(slot) = digits.get_mut(low_index) {
            *slot = byte & 0x0f;
        }
    }

    let mut checksum = 0_u16;
    for digit in digits.iter().take(64) {
        checksum = checksum.wrapping_add(15_u16.saturating_sub(u16::from(*digit)));
    }
    if let Some(slot) = digits.get_mut(64) {
        *slot = u8::try_from(checksum.wrapping_shr(8) & 0x0f).unwrap_or(0);
    }
    if let Some(slot) = digits.get_mut(65) {
        *slot = u8::try_from(checksum.wrapping_shr(4) & 0x0f).unwrap_or(0);
    }
    if let Some(slot) = digits.get_mut(66) {
        *slot = u8::try_from(checksum & 0x0f).unwrap_or(0);
    }
    digits
}

fn wots_sign(
    seed: &[u8; 32],
    leaf_index: u16,
    digits: &[u8; WOTS_CHAINS],
) -> Result<[u8; WOTS_SIGNATURE_BYTES], CryptoError> {
    let mut signature = [0_u8; WOTS_SIGNATURE_BYTES];
    for (chain_index, (slot, digit)) in signature
        .as_chunks_mut::<32>()
        .0
        .iter_mut()
        .zip(digits.iter())
        .enumerate()
    {
        let chain_u8 = u8::try_from(chain_index).map_err(|_| CryptoError::InvalidLength)?;
        let mut value = secret(seed, leaf_index, chain_u8);
        for _ in 0..*digit {
            value = chain_hash(&value);
        }
        slot.copy_from_slice(&value);
    }
    Ok(signature)
}

fn wots_verify(signature: &[u8], digits: &[u8; WOTS_CHAINS]) -> Result<[u8; 32], CryptoError> {
    if signature.len() != WOTS_SIGNATURE_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let mut hasher = Hasher::new_derive_key(WOTS_PK_CONTEXT);
    for (slot, digit) in signature.as_chunks::<32>().0.iter().zip(digits.iter()) {
        let mut value = [0_u8; 32];
        value.copy_from_slice(slot);
        let steps = WOTS_CHAIN_LEN.saturating_sub(*digit);
        for _ in 0..steps {
            value = chain_hash(&value);
        }
        hasher.update(&value);
    }
    Ok(hasher.finalize().to_bytes())
}

fn signature_checksum(body: &[u8]) -> Result<[u8; SIGNATURE_CHECKSUM_BYTES], CryptoError> {
    let hash = derive_key32(CHECKSUM_CONTEXT, body);
    let mut checksum = [0_u8; SIGNATURE_CHECKSUM_BYTES];
    let source = hash
        .as_bytes()
        .get(..SIGNATURE_CHECKSUM_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    checksum.copy_from_slice(source);
    Ok(checksum)
}

const _: [(); QHS_PUBLIC_KEY_BYTES] = [(); size_of::<QhsPublicKey>()];
const _: [(); QHS_SIGNATURE_BYTES] = [(); size_of::<QhsSignature>()];
const _: [(); QHS_PRIVATE_KEY_BYTES] = [(); size_of::<QhsPrivateKey>()];
const _: [(); 2408] = [(); QHS_SIGNATURE_BYTES];

#[cfg(test)]
mod tests {
    use super::{
        QHS_MAX_SIGNATURES, QHS_SIGNATURE_BYTES, QhsPrivateKey, QhsPublicKey, QhsSignature, keygen,
    };
    use core::mem::size_of;
    use qwp_core::CryptoError;

    const SEED: [u8; 32] = [7_u8; 32];

    #[test]
    fn sign_verify_round_trip() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"qWp QHS-1 message").unwrap();
        assert_eq!(public_key.verify(b"qWp QHS-1 message", &signature), Ok(()));
        assert_eq!(signature.leaf_index(), Ok(0));
        assert_eq!(private_key.next_leaf(), 1);
    }

    #[test]
    fn rejects_wrong_message() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"message-a").unwrap();
        assert_eq!(
            public_key.verify(b"message-b", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"message").unwrap();
        let mut bytes = signature.to_bytes();
        bytes[10] ^= 1;
        let tampered = QhsSignature::from_bytes(bytes);
        assert_eq!(
            public_key.verify(b"message", &tampered),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let (mut private_key, _public_key) = keygen(&SEED).unwrap();
        let (_, other_public_key) = keygen(&[9_u8; 32]).unwrap();
        let signature = private_key.sign(b"message").unwrap();
        assert_eq!(
            other_public_key.verify(b"message", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_exhausted_key() {
        let (private_key, _public_key) = keygen(&SEED).unwrap();
        let mut bytes = private_key.to_bytes();
        bytes[36..38].copy_from_slice(&QHS_MAX_SIGNATURES.to_le_bytes());
        let mut exhausted = QhsPrivateKey::from_bytes(&bytes).unwrap();
        assert!(exhausted.is_exhausted());
        assert_eq!(exhausted.sign(b"message"), Err(CryptoError::KeyExhausted));
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let (private_key, _public_key) = keygen(&SEED).unwrap();
        let debug = std::format!("{private_key:?}");
        assert!(debug.contains("QhsPrivateKey"));
        assert!(!debug.contains("seed"));
    }

    #[test]
    fn signature_size_is_exact() {
        assert_eq!(size_of::<QhsSignature>(), QHS_SIGNATURE_BYTES);
        assert_eq!(QHS_SIGNATURE_BYTES, 2408);
    }

    #[test]
    fn public_key_round_trip() {
        let (_, public_key) = keygen(&SEED).unwrap();
        let bytes = public_key.to_bytes();
        assert_eq!(QhsPublicKey::from_bytes(&bytes), Ok(public_key));
    }
}
