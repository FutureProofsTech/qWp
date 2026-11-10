//! QHS-3: qWp's custom hash-based signature.
//!
//! QHS-3 is a stateful Winternitz one-time signature (WOTS) with a Merkle
//! authentication tree. It is built only on the in-tree BLAKE3 implementation.
//! The security proof is in `docs/10-qhs3.md`.

use core::fmt;
use core::mem::size_of;

use qwp_core::CryptoError;
use qwp_hash::{Hasher, derive_key32};

/// Number of base-64 message digits.
const MESSAGE_DIGITS: usize = 43;
/// Number of base-64 checksum digits.
const CHECKSUM_DIGITS: usize = 2;
/// Number of WOTS hash chains.
const WOTS_CHAINS: usize = MESSAGE_DIGITS + CHECKSUM_DIGITS;
/// Maximum WOTS chain steps.
const WOTS_CHAIN_LEN: u8 = 63;
/// Bytes in the WOTS signature.
const WOTS_SIGNATURE_BYTES: usize = WOTS_CHAINS * 32;
/// Merkle tree height.
const TREE_HEIGHT: usize = 12;
/// Number of Merkle leaves.
const LEAF_COUNT: usize = 4096;
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
pub const QHS3_PUBLIC_KEY_BYTES: usize = 64;
/// Private key size in bytes.
pub const QHS3_PRIVATE_KEY_BYTES: usize = 64;
/// Signature size in bytes.
pub const QHS3_SIGNATURE_BYTES: usize = CHECKSUM_OFFSET + SIGNATURE_CHECKSUM_BYTES;
/// Number of signatures available from one private key.
pub const QHS3_MAX_SIGNATURES: u16 = 4096;
/// Number of Merkle leaves per key.
pub const QHS3_LEAF_COUNT: usize = LEAF_COUNT;
/// Bytes per Merkle leaf.
pub const QHS3_LEAF_BYTES: usize = 32;
/// Number of internal Merkle nodes in a QHS-3 tree.
pub const QHS3_TREE_NODES: usize = LEAF_COUNT - 1;

const SECRET_CONTEXT: &[u8] = b"qWp QHS-3 secret";
const CHAIN_CONTEXT: &[u8] = b"qWp QHS-3 chain";
const WOTS_PK_CONTEXT: &[u8] = b"qWp QHS-3 wots-pk";
const LEAF_CONTEXT: &[u8] = b"qWp QHS-3 leaf";
const NODE_CONTEXT: &[u8] = b"qWp QHS-3 node";
const MESSAGE_CONTEXT: &[u8] = b"qWp QHS-3 message";
const CHECKSUM_CONTEXT: &[u8] = b"qWp QHS-3 signature-checksum";

/// A QHS-3 public key: a Merkle root and algorithm metadata.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs3PublicKey {
    bytes: [u8; QHS3_PUBLIC_KEY_BYTES],
}

impl Qhs3PublicKey {
    /// Creates a public key from a Merkle root.
    #[must_use]
    #[inline]
    pub fn from_root(root: [u8; 32]) -> Self {
        let mut bytes = [0_u8; QHS3_PUBLIC_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..4) {
            slot.copy_from_slice(&[3, 3, u8::try_from(TREE_HEIGHT).unwrap_or(0), 0]);
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
    pub fn from_bytes(bytes: &[u8; QHS3_PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        let version = bytes.first().copied().ok_or(CryptoError::InvalidLength)?;
        let algorithm = bytes.get(1).copied().ok_or(CryptoError::InvalidLength)?;
        let height = bytes.get(2).copied().ok_or(CryptoError::InvalidLength)?;
        let reserved = bytes.get(3).copied().ok_or(CryptoError::InvalidLength)?;
        let tail = bytes
            .get(36..QHS3_PUBLIC_KEY_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        if version != 3
            || algorithm != 3
            || height != u8::try_from(TREE_HEIGHT).unwrap_or(0)
            || reserved != 0
            || tail.iter().any(|byte| *byte != 0)
        {
            return Err(CryptoError::InvalidLength);
        }
        let mut output = [0_u8; QHS3_PUBLIC_KEY_BYTES];
        output.copy_from_slice(bytes);
        Ok(Self { bytes: output })
    }

    /// Returns the exact 64-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS3_PUBLIC_KEY_BYTES] {
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

    /// Verifies a QHS-3 signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerificationFailed`] for an invalid signature.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &Qhs3Signature) -> Result<(), CryptoError> {
        let bytes = signature.as_bytes();
        if bytes.first() != Some(&3) || bytes.get(1) != Some(&3) {
            return Err(CryptoError::VerificationFailed);
        }
        let leaf_bytes = bytes.get(2..4).ok_or(CryptoError::VerificationFailed)?;
        let mut leaf_word = [0_u8; 2];
        leaf_word.copy_from_slice(leaf_bytes);
        let leaf_index = u16::from_le_bytes(leaf_word);
        if leaf_index >= QHS3_MAX_SIGNATURES {
            return Err(CryptoError::VerificationFailed);
        }

        let body = bytes
            .get(..CHECKSUM_BODY_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let expected_checksum = signature_checksum(body)?;
        let actual_checksum = bytes
            .get(CHECKSUM_OFFSET..QHS3_SIGNATURE_BYTES)
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

/// A QHS-3 private key.
///
/// The key is stateful: each signature consumes one Merkle leaf. It is not
/// `Clone`, is not printable, and is wiped best-effort on drop.
pub struct Qhs3PrivateKey {
    seed: [u8; 32],
    next_leaf: u16,
    reserved: [u8; 30],
}

impl Qhs3PrivateKey {
    /// Creates a private key from a seed and a starting leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if `next_leaf` exceeds [`QHS3_MAX_SIGNATURES`].
    #[inline]
    pub const fn from_parts(seed: [u8; 32], next_leaf: u16) -> Result<Self, CryptoError> {
        if next_leaf > QHS3_MAX_SIGNATURES {
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
    pub fn from_bytes(bytes: &[u8; QHS3_PRIVATE_KEY_BYTES]) -> Result<Self, CryptoError> {
        let version = bytes.first().copied().ok_or(CryptoError::InvalidLength)?;
        let algorithm = bytes.get(1).copied().ok_or(CryptoError::InvalidLength)?;
        let height = bytes.get(2).copied().ok_or(CryptoError::InvalidLength)?;
        let reserved = bytes.get(3).copied().ok_or(CryptoError::InvalidLength)?;
        if version != 3
            || algorithm != 3
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
    pub fn to_bytes(&self) -> [u8; QHS3_PRIVATE_KEY_BYTES] {
        let mut bytes = [0_u8; QHS3_PRIVATE_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..4) {
            slot.copy_from_slice(&[3, 3, u8::try_from(TREE_HEIGHT).unwrap_or(0), 0]);
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

    /// Returns the secret seed for host-side leaf derivation.
    ///
    /// The caller must not log or expose this value.
    #[must_use]
    #[inline]
    pub const fn seed(&self) -> &[u8; 32] {
        &self.seed
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
        self.next_leaf >= QHS3_MAX_SIGNATURES
    }

    /// Signs a message and consumes one Merkle leaf.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 256 signatures.
    #[inline]
    pub fn sign(&mut self, message: &[u8]) -> Result<Qhs3Signature, CryptoError> {
        if self.is_exhausted() {
            return Err(CryptoError::KeyExhausted);
        }
        let leaf_index = self.next_leaf;
        self.next_leaf = self.next_leaf.saturating_add(1);

        let digits = message_digits(message);
        let wots_signature = wots_sign(&self.seed, leaf_index, &digits)?;
        let auth_path = auth_path_from_seed(&self.seed, leaf_index)?;
        build_signature(leaf_index, &wots_signature, &auth_path)
    }

    /// Signs a message using precomputed Merkle leaves.
    ///
    /// The leaves must be the exact leaves derived from this key's seed. The
    /// CLI validates a fingerprinted cache before calling this. Caching is a
    /// performance optimization only; it does not change the signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 4,096 signatures.
    #[inline]
    pub fn sign_with_leaves(
        &mut self,
        message: &[u8],
        leaves: &[[u8; 32]],
    ) -> Result<Qhs3Signature, CryptoError> {
        if self.is_exhausted() {
            return Err(CryptoError::KeyExhausted);
        }
        let leaf_index = self.next_leaf;
        self.next_leaf = self.next_leaf.saturating_add(1);

        let digits = message_digits(message);
        let wots_signature = wots_sign(&self.seed, leaf_index, &digits)?;
        let auth_path = auth_path_from_leaves(leaves, leaf_index)?;
        build_signature(leaf_index, &wots_signature, &auth_path)
    }

    /// Signs a message using a precomputed Merkle authentication path.
    ///
    /// This is the QHS-3.1 fast path. The path must be the exact path for this
    /// key's next leaf. The CLI validates a fingerprinted tree cache before
    /// calling this. It does not change the signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 4,096 signatures.
    #[inline]
    pub fn sign_with_auth_path(
        &mut self,
        message: &[u8],
        auth_path: &[[u8; 32]; TREE_HEIGHT],
    ) -> Result<Qhs3Signature, CryptoError> {
        if self.is_exhausted() {
            return Err(CryptoError::KeyExhausted);
        }
        let leaf_index = self.next_leaf;
        self.next_leaf = self.next_leaf.saturating_add(1);

        let digits = message_digits(message);
        let wots_signature = wots_sign(&self.seed, leaf_index, &digits)?;
        build_signature(leaf_index, &wots_signature, auth_path)
    }
}

fn build_signature(
    leaf_index: u16,
    wots_signature: &[u8; WOTS_SIGNATURE_BYTES],
    auth_path: &[[u8; 32]; TREE_HEIGHT],
) -> Result<Qhs3Signature, CryptoError> {
    let mut bytes = [0_u8; QHS3_SIGNATURE_BYTES];

    if let Some(slot) = bytes.get_mut(0..4) {
        slot.copy_from_slice(&[3, 3, 0, 0]);
    }
    if let Some(slot) = bytes.get_mut(2..4) {
        slot.copy_from_slice(&leaf_index.to_le_bytes());
    }
    if let Some(slot) = bytes.get_mut(WOTS_OFFSET..AUTH_OFFSET) {
        slot.copy_from_slice(wots_signature);
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
    if let Some(slot) = bytes.get_mut(CHECKSUM_OFFSET..QHS3_SIGNATURE_BYTES) {
        slot.copy_from_slice(&checksum);
    }

    Ok(Qhs3Signature { bytes })
}

impl Drop for Qhs3PrivateKey {
    #[inline]
    fn drop(&mut self) {
        self.seed.fill(0);
        self.next_leaf = 0;
    }
}

impl fmt::Debug for Qhs3PrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Qhs3PrivateKey")
            .field("next_leaf", &self.next_leaf)
            .finish_non_exhaustive()
    }
}

/// A QHS-3 signature.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs3Signature {
    bytes: [u8; QHS3_SIGNATURE_BYTES],
}

impl Qhs3Signature {
    /// Creates a signature from its exact 2408-byte representation.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; QHS3_SIGNATURE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Returns the exact 2408-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS3_SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; QHS3_SIGNATURE_BYTES] {
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

/// Computes one Merkle leaf from the seed.
///
/// # Errors
///
/// Returns an error when `leaf_index` is outside `0..256`.
#[inline]
pub fn qhs3_leaf(seed: &[u8; 32], leaf_index: u16) -> Result<[u8; 32], CryptoError> {
    if leaf_index >= QHS3_MAX_SIGNATURES {
        return Err(CryptoError::InvalidLength);
    }
    let wots_pk = wots_pk_hash(seed, leaf_index);
    Ok(leaf_hash(leaf_index, &wots_pk))
}

/// Builds a key pair from precomputed Merkle leaves.
///
/// The slice must contain exactly 4,096 leaves derived from `seed`. This is a
/// performance API used by the host key store after cache validation.
///
/// # Errors
///
/// Returns an error if the slice length is not exactly 4,096.
#[inline]
pub fn qhs3_keygen_from_leaves(
    seed: &[u8; 32],
    leaves: &[[u8; 32]],
) -> Result<(Qhs3PrivateKey, Qhs3PublicKey), CryptoError> {
    if leaves.len() != LEAF_COUNT {
        return Err(CryptoError::InvalidLength);
    }
    let root = range_root_from_leaves(leaves, 0, LEAF_COUNT)?;
    let private_key = Qhs3PrivateKey::from_parts(*seed, 0)?;
    let public_key = Qhs3PublicKey::from_root(root);
    Ok((private_key, public_key))
}

/// Generates a QHS-3 key pair from a 32-byte seed.
///
/// This sequential reference path computes the 4,096 leaves without a large
/// stack buffer. Hosts should use the parallel leaf API and
/// [`qhs3_keygen_from_leaves`].
///
/// # Errors
///
/// Returns an internal length error if a range is malformed.
#[inline]
pub fn keygen(seed: &[u8; 32]) -> Result<(Qhs3PrivateKey, Qhs3PublicKey), CryptoError> {
    let root = range_root_from_seed(seed, 0, LEAF_COUNT)?;
    let private_key = Qhs3PrivateKey::from_parts(*seed, 0)?;
    let public_key = Qhs3PublicKey::from_root(root);
    Ok((private_key, public_key))
}

/// Builds the internal Merkle nodes for a QHS-3 tree.
///
/// `nodes` must have at least [`QHS3_TREE_NODES`] entries. The nodes are stored
/// level by level: 2,048 nodes at level 1, 1,024 at level 2, and so on, ending
/// with the root at index 4,094. Returns the root.
///
/// # Errors
///
/// Returns an error if the leaf or node slice has the wrong length.
#[inline]
pub fn qhs3_build_tree(
    leaves: &[[u8; 32]],
    nodes: &mut [[u8; 32]],
) -> Result<[u8; 32], CryptoError> {
    if leaves.len() != LEAF_COUNT || nodes.len() < QHS3_TREE_NODES {
        return Err(CryptoError::InvalidLength);
    }

    let mut previous_offset = 0_usize;
    let mut previous_count = LEAF_COUNT.checked_shr(1).unwrap_or(0);
    for index in 0..previous_count {
        let left_index = index.checked_mul(2).unwrap_or(0);
        let right_index = left_index.checked_add(1).unwrap_or(0);
        let left = *leaves.get(left_index).ok_or(CryptoError::InvalidLength)?;
        let right = *leaves.get(right_index).ok_or(CryptoError::InvalidLength)?;
        let parent = node_hash(&left, &right);
        if let Some(slot) = nodes.get_mut(index) {
            *slot = parent;
        }
    }

    for level in 2..=TREE_HEIGHT {
        let count = previous_count.checked_shr(1).unwrap_or(0);
        let shift = u32::try_from(level.saturating_sub(1)).unwrap_or(0);
        let offset = LEAF_COUNT.saturating_sub(LEAF_COUNT.checked_shr(shift).unwrap_or(0));
        for index in 0..count {
            let left_index = previous_offset
                .checked_add(index.checked_mul(2).unwrap_or(0))
                .unwrap_or(0);
            let right_index = left_index.checked_add(1).unwrap_or(0);
            let left = *nodes.get(left_index).ok_or(CryptoError::InvalidLength)?;
            let right = *nodes.get(right_index).ok_or(CryptoError::InvalidLength)?;
            let parent = node_hash(&left, &right);
            if let Some(slot) = nodes.get_mut(offset.checked_add(index).unwrap_or(0)) {
                *slot = parent;
            }
        }
        previous_offset = offset;
        previous_count = count;
    }

    nodes
        .get(QHS3_TREE_NODES.saturating_sub(1))
        .copied()
        .ok_or(CryptoError::InvalidLength)
}

/// Extracts the QHS-3 authentication path from a precomputed tree.
///
/// The leaves and nodes must match the same tree. This is the QHS-3.1 fast
/// path; it performs O(log N) work instead of rebuilding the tree.
///
/// # Errors
///
/// Returns an error if a slice length or leaf index is invalid.
#[inline]
pub fn qhs3_auth_path_from_tree(
    leaves: &[[u8; 32]],
    nodes: &[[u8; 32]],
    leaf_index: u16,
) -> Result<[[u8; 32]; TREE_HEIGHT], CryptoError> {
    if leaves.len() != LEAF_COUNT
        || nodes.len() < QHS3_TREE_NODES
        || leaf_index >= QHS3_MAX_SIGNATURES
    {
        return Err(CryptoError::InvalidLength);
    }

    let mut path = [[0_u8; 32]; TREE_HEIGHT];
    let sibling_leaf_index = usize::from(leaf_index) ^ 1;
    let sibling_leaf = *leaves
        .get(sibling_leaf_index)
        .ok_or(CryptoError::InvalidLength)?;
    if let Some(slot) = path.first_mut() {
        *slot = sibling_leaf;
    }

    for level in 1..TREE_HEIGHT {
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let count = LEAF_COUNT.checked_shr(level_u32).unwrap_or(0);
        let shift = u32::try_from(level.saturating_sub(1)).unwrap_or(0);
        let offset = LEAF_COUNT.saturating_sub(LEAF_COUNT.checked_shr(shift).unwrap_or(0));
        let node_index = usize::from(leaf_index).checked_shr(level_u32).unwrap_or(0) ^ 1;
        if node_index >= count {
            return Err(CryptoError::InvalidLength);
        }
        let sibling = *nodes
            .get(offset.checked_add(node_index).unwrap_or(0))
            .ok_or(CryptoError::InvalidLength)?;
        if let Some(slot) = path.get_mut(level) {
            *slot = sibling;
        }
    }

    Ok(path)
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

fn range_root_from_seed(
    seed: &[u8; 32],
    start: usize,
    count: usize,
) -> Result<[u8; 32], CryptoError> {
    if count == 0 || start.saturating_add(count) > LEAF_COUNT {
        return Err(CryptoError::InvalidLength);
    }
    if count == 1 {
        let leaf_index = u16::try_from(start).map_err(|_| CryptoError::InvalidLength)?;
        return qhs3_leaf(seed, leaf_index);
    }
    let half = count.checked_shr(1).unwrap_or(0);
    if half == 0 || half.checked_mul(2).unwrap_or(0) != count {
        return Err(CryptoError::InvalidLength);
    }
    let left = range_root_from_seed(seed, start, half)?;
    let right = range_root_from_seed(seed, start.checked_add(half).unwrap_or(0), half)?;
    Ok(node_hash(&left, &right))
}

fn range_root_from_leaves(
    leaves: &[[u8; 32]],
    start: usize,
    count: usize,
) -> Result<[u8; 32], CryptoError> {
    if count == 0 || start.saturating_add(count) > leaves.len() {
        return Err(CryptoError::InvalidLength);
    }
    if count == 1 {
        return leaves.get(start).copied().ok_or(CryptoError::InvalidLength);
    }
    let half = count.checked_shr(1).unwrap_or(0);
    if half == 0 || half.checked_mul(2).unwrap_or(0) != count {
        return Err(CryptoError::InvalidLength);
    }
    let left = range_root_from_leaves(leaves, start, half)?;
    let right = range_root_from_leaves(leaves, start.checked_add(half).unwrap_or(0), half)?;
    Ok(node_hash(&left, &right))
}

fn auth_path_from_seed(
    seed: &[u8; 32],
    leaf_index: u16,
) -> Result<[[u8; 32]; TREE_HEIGHT], CryptoError> {
    if leaf_index >= QHS3_MAX_SIGNATURES {
        return Err(CryptoError::InvalidLength);
    }
    let mut path = [[0_u8; 32]; TREE_HEIGHT];
    for level in 0..TREE_HEIGHT {
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let sibling_block = usize::from(leaf_index).checked_shr(level_u32).unwrap_or(0) ^ 1;
        let start = sibling_block.checked_shl(level_u32).unwrap_or(0);
        let count = 1_usize.checked_shl(level_u32).unwrap_or(0);
        let sibling = range_root_from_seed(seed, start, count)?;
        if let Some(slot) = path.get_mut(level) {
            *slot = sibling;
        }
    }
    Ok(path)
}

fn auth_path_from_leaves(
    leaves: &[[u8; 32]],
    leaf_index: u16,
) -> Result<[[u8; 32]; TREE_HEIGHT], CryptoError> {
    if leaves.len() != LEAF_COUNT || leaf_index >= QHS3_MAX_SIGNATURES {
        return Err(CryptoError::InvalidLength);
    }
    let mut path = [[0_u8; 32]; TREE_HEIGHT];
    for level in 0..TREE_HEIGHT {
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let sibling_block = usize::from(leaf_index).checked_shr(level_u32).unwrap_or(0) ^ 1;
        let start = sibling_block.checked_shl(level_u32).unwrap_or(0);
        let count = 1_usize.checked_shl(level_u32).unwrap_or(0);
        let sibling = range_root_from_leaves(leaves, start, count)?;
        if let Some(slot) = path.get_mut(level) {
            *slot = sibling;
        }
    }
    Ok(path)
}

fn message_digits(message: &[u8]) -> [u8; WOTS_CHAINS] {
    let digest = derive_key32(MESSAGE_CONTEXT, message).to_bytes();
    let mut digits = [0_u8; WOTS_CHAINS];

    // 43 base-64 digits encode the 256-bit digest with two leading zero bits.
    for index in 0..MESSAGE_DIGITS {
        let mut value = 0_u8;
        for offset in 0..6 {
            let padded_bit = index
                .checked_mul(6)
                .unwrap_or(0)
                .checked_add(offset)
                .unwrap_or(0);
            let bit = if padded_bit < 2 {
                0
            } else {
                let digest_bit = padded_bit.saturating_sub(2);
                let byte_index = digest_bit.checked_div(8).unwrap_or(0);
                let shift = 7_u32.saturating_sub(u32::try_from(digest_bit % 8).unwrap_or(0));
                digest
                    .get(byte_index)
                    .map_or(0, |byte| byte.wrapping_shr(shift) & 1)
            };
            value = value.wrapping_shl(1) | bit;
        }
        if let Some(slot) = digits.get_mut(index) {
            *slot = value;
        }
    }

    // Two base-64 checksum digits encode the value in 0..=2709.
    let mut checksum = 0_u16;
    for digit in digits.iter().take(MESSAGE_DIGITS) {
        checksum = checksum.wrapping_add(63_u16.saturating_sub(u16::from(*digit)));
    }
    if let Some(slot) = digits.get_mut(MESSAGE_DIGITS) {
        *slot = u8::try_from(checksum.wrapping_shr(6)).unwrap_or(0);
    }
    if let Some(slot) = digits.get_mut(MESSAGE_DIGITS.checked_add(1).unwrap_or(0)) {
        *slot = u8::try_from(checksum & 0x3f).unwrap_or(0);
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

const _: [(); QHS3_PUBLIC_KEY_BYTES] = [(); size_of::<Qhs3PublicKey>()];
const _: [(); QHS3_SIGNATURE_BYTES] = [(); size_of::<Qhs3Signature>()];
const _: [(); QHS3_PRIVATE_KEY_BYTES] = [(); size_of::<Qhs3PrivateKey>()];
const _: [(); 1832] = [(); QHS3_SIGNATURE_BYTES];

#[cfg(test)]
mod tests {
    #![allow(
        clippy::std_instead_of_alloc,
        reason = "tests use std for OnceLock and Vec"
    )]

    use super::{
        CHAIN_CONTEXT, CHECKSUM_CONTEXT, LEAF_CONTEXT, MESSAGE_CONTEXT, NODE_CONTEXT,
        QHS3_MAX_SIGNATURES, QHS3_SIGNATURE_BYTES, QHS3_TREE_NODES, Qhs3PrivateKey, Qhs3PublicKey,
        Qhs3Signature, SECRET_CONTEXT, WOTS_PK_CONTEXT, qhs3_auth_path_from_tree, qhs3_build_tree,
        qhs3_keygen_from_leaves, qhs3_leaf,
    };
    use core::mem::size_of;
    use qwp_core::CryptoError;
    use qwp_hash::hash32;
    use std::sync::OnceLock;
    use std::vec;
    use std::vec::Vec;

    const SEED: [u8; 32] = [7_u8; 32];

    static LEAVES: OnceLock<Vec<[u8; 32]>> = OnceLock::new();

    fn leaves() -> &'static [[u8; 32]] {
        LEAVES.get_or_init(|| {
            let mut values = vec![[0_u8; 32]; super::LEAF_COUNT];
            let threads = std::thread::available_parallelism()
                .map_or(1, core::num::NonZero::get)
                .min(16);
            let chunk_size = super::LEAF_COUNT.div_ceil(threads);
            std::thread::scope(|scope| {
                for (chunk_index, chunk) in values.chunks_mut(chunk_size).enumerate() {
                    let base = chunk_index * chunk_size;
                    let _handle = scope.spawn(move || {
                        for (offset, slot) in chunk.iter_mut().enumerate() {
                            let index = u16::try_from(base + offset).unwrap();
                            *slot = qhs3_leaf(&SEED, index).unwrap();
                        }
                    });
                }
            });
            values
        })
    }

    fn key_pair() -> (Qhs3PrivateKey, Qhs3PublicKey) {
        qhs3_keygen_from_leaves(&SEED, leaves()).unwrap()
    }

    fn sign(private_key: &mut Qhs3PrivateKey, message: &[u8]) -> Qhs3Signature {
        private_key.sign_with_leaves(message, leaves()).unwrap()
    }

    #[test]
    fn sign_verify_round_trip() {
        let (mut private_key, public_key) = key_pair();
        let signature = sign(&mut private_key, b"qWp QHS-3 message");
        assert_eq!(public_key.verify(b"qWp QHS-3 message", &signature), Ok(()));
        assert_eq!(signature.leaf_index(), Ok(0));
        assert_eq!(private_key.next_leaf(), 1);
    }

    #[test]
    fn rejects_wrong_message() {
        let (mut private_key, public_key) = key_pair();
        let signature = sign(&mut private_key, b"message-a");
        assert_eq!(
            public_key.verify(b"message-b", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let (mut private_key, public_key) = key_pair();
        let signature = sign(&mut private_key, b"message");
        let mut bytes = signature.to_bytes();
        bytes[10] ^= 1;
        let tampered = Qhs3Signature::from_bytes(bytes);
        assert_eq!(
            public_key.verify(b"message", &tampered),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let (mut private_key, public_key) = key_pair();
        let signature = sign(&mut private_key, b"message");
        let mut wrong_bytes = public_key.to_bytes();
        wrong_bytes[4] ^= 1;
        let other_public_key = Qhs3PublicKey::from_bytes(&wrong_bytes).unwrap();
        assert_eq!(
            other_public_key.verify(b"message", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_exhausted_key() {
        let mut exhausted = Qhs3PrivateKey::from_parts(SEED, QHS3_MAX_SIGNATURES).unwrap();
        assert!(exhausted.is_exhausted());
        assert_eq!(exhausted.sign(b"message"), Err(CryptoError::KeyExhausted));
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let (private_key, _public_key) = key_pair();
        let debug = std::format!("{private_key:?}");
        assert!(debug.contains("Qhs3PrivateKey"));
        assert!(!debug.contains("seed"));
    }

    #[test]
    fn signature_size_is_exact() {
        assert_eq!(size_of::<Qhs3Signature>(), QHS3_SIGNATURE_BYTES);
        assert_eq!(QHS3_SIGNATURE_BYTES, 1832);
    }

    #[test]
    fn domain_contexts_are_distinct() {
        let contexts = [
            SECRET_CONTEXT,
            CHAIN_CONTEXT,
            WOTS_PK_CONTEXT,
            LEAF_CONTEXT,
            NODE_CONTEXT,
            MESSAGE_CONTEXT,
            CHECKSUM_CONTEXT,
        ];
        for (index, left) in contexts.iter().enumerate() {
            for right in contexts.iter().skip(index.saturating_add(1)) {
                assert_ne!(left, right);
            }
        }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn cached_leaves_match_sequential_keygen() {
        let cached = leaves();
        assert_eq!(qhs3_leaf(&SEED, 0).unwrap(), cached[0]);
        let (_, sequential_public) = super::keygen(&SEED).unwrap();
        let (_, cached_public) = qhs3_keygen_from_leaves(&SEED, cached).unwrap();
        assert_eq!(sequential_public, cached_public);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn uncached_signing_matches_cached() {
        let mut uncached = Qhs3PrivateKey::from_parts(SEED, 1).unwrap();
        let mut cached = Qhs3PrivateKey::from_parts(SEED, 1).unwrap();
        let uncached_signature = uncached.sign(b"cached").unwrap();
        let cached_signature = cached.sign_with_leaves(b"cached", leaves()).unwrap();
        assert_eq!(uncached_signature, cached_signature);
    }

    #[test]
    fn message_digits_padding_matches_digest_prefix() {
        let mut found = false;
        for value in 0_u8..=255 {
            let message = [value];
            let digest = qwp_hash::derive_key32(MESSAGE_CONTEXT, &message).to_bytes();
            if digest.first().is_some_and(|byte| byte & 0x80 != 0) {
                let digits = super::message_digits(&message);
                assert_eq!(digits.first(), Some(&(digest[0] >> 4)));
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[test]
    fn known_message_digits() {
        assert_eq!(
            super::message_digits(b"qWp QHS-3 KAT"),
            [
                1, 2, 9, 20, 28, 44, 32, 50, 8, 60, 58, 48, 20, 9, 37, 14, 18, 19, 42, 26, 45, 4,
                26, 38, 13, 3, 24, 2, 10, 50, 25, 59, 19, 14, 40, 57, 46, 12, 6, 1, 25, 5, 55, 24,
                49,
            ]
        );
    }

    #[test]
    fn private_key_round_trip() {
        let (private_key, _) = key_pair();
        let bytes = private_key.to_bytes();
        assert_eq!(&bytes[..4], &[3, 3, 12, 0]);
        assert_eq!(&bytes[4..36], &SEED);
        assert_eq!(&bytes[36..38], &[0, 0]);
        let parsed = Qhs3PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.next_leaf(), private_key.next_leaf());
        assert_eq!(parsed.seed(), &SEED);
    }

    #[test]
    fn tree_rejects_bad_lengths() {
        let leaves = leaves();
        let mut nodes = vec![[0_u8; 32]; QHS3_TREE_NODES];
        assert!(qhs3_build_tree(&leaves[..super::LEAF_COUNT - 1], &mut nodes).is_err());
        let mut short_nodes = vec![[0_u8; 32]; QHS3_TREE_NODES - 1];
        assert!(qhs3_build_tree(leaves, &mut short_nodes).is_err());
        let mut large_nodes = vec![[0_u8; 32]; QHS3_TREE_NODES + 1];
        assert!(qhs3_build_tree(leaves, &mut large_nodes).is_ok());
        assert!(qhs3_auth_path_from_tree(&leaves[..super::LEAF_COUNT - 1], &nodes, 0).is_err());
        assert!(qhs3_auth_path_from_tree(leaves, &nodes[..QHS3_TREE_NODES - 1], 0).is_err());
        assert!(qhs3_auth_path_from_tree(leaves, &nodes, QHS3_MAX_SIGNATURES).is_err());
    }

    #[test]
    fn range_roots_reject_invalid_ranges() {
        assert!(super::range_root_from_seed(&SEED, 0, 0).is_err());
        assert!(super::range_root_from_seed(&SEED, super::LEAF_COUNT, 1).is_err());
        assert!(super::range_root_from_seed(&SEED, 0, 3).is_err());
        let leaves = leaves();
        assert!(super::range_root_from_leaves(leaves, 0, 0).is_err());
        assert!(super::range_root_from_leaves(leaves, super::LEAF_COUNT, 1).is_err());
        assert!(super::range_root_from_leaves(leaves, 0, 3).is_err());
        assert!(super::auth_path_from_leaves(&leaves[..super::LEAF_COUNT - 1], 0).is_err());
        assert!(super::auth_path_from_leaves(leaves, QHS3_MAX_SIGNATURES).is_err());
    }

    #[test]
    fn tree_cache_matches_leaf_auth_paths_and_signatures() {
        let leaves = leaves();
        let mut nodes = vec![[0_u8; 32]; QHS3_TREE_NODES];
        let root = qhs3_build_tree(leaves, &mut nodes).unwrap();
        let (_, public_key) = key_pair();
        assert_eq!(public_key, Qhs3PublicKey::from_root(root));

        for leaf_index in [0_u16, 1, 42, 2048, 4095] {
            let from_tree = qhs3_auth_path_from_tree(leaves, &nodes, leaf_index).unwrap();
            let from_leaves = super::auth_path_from_leaves(leaves, leaf_index).unwrap();
            assert_eq!(from_tree, from_leaves);

            let mut tree_key = Qhs3PrivateKey::from_parts(SEED, leaf_index).unwrap();
            let mut leaf_key = Qhs3PrivateKey::from_parts(SEED, leaf_index).unwrap();
            let tree_signature = tree_key
                .sign_with_auth_path(b"tree-cache", &from_tree)
                .unwrap();
            let leaf_signature = leaf_key.sign_with_leaves(b"tree-cache", leaves).unwrap();
            assert_eq!(tree_signature, leaf_signature);
        }
    }

    #[test]
    fn public_key_round_trip() {
        let (_, public_key) = key_pair();
        let bytes = public_key.to_bytes();
        assert_eq!(Qhs3PublicKey::from_bytes(&bytes), Ok(public_key));
    }

    #[test]
    fn public_key_rejects_bad_metadata() {
        let (_, public_key) = key_pair();
        let original = public_key.to_bytes();
        let mut bytes = original;
        bytes[0] = 2;
        assert!(Qhs3PublicKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[1] = 2;
        assert!(Qhs3PublicKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[2] = 11;
        assert!(Qhs3PublicKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[3] = 1;
        assert!(Qhs3PublicKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[36] = 1;
        assert!(Qhs3PublicKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn private_key_rejects_bad_metadata_and_counter() {
        let original = Qhs3PrivateKey::from_parts([0_u8; 32], 0)
            .unwrap()
            .to_bytes();
        let mut bytes = original;
        bytes[0] = 2;
        assert!(Qhs3PrivateKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[1] = 2;
        assert!(Qhs3PrivateKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[2] = 11;
        assert!(Qhs3PrivateKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[3] = 1;
        assert!(Qhs3PrivateKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[38] = 1;
        assert!(Qhs3PrivateKey::from_bytes(&bytes).is_err());
        bytes = original;
        bytes[36..38].copy_from_slice(&4097_u16.to_le_bytes());
        assert!(Qhs3PrivateKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn signature_rejects_bad_version_and_checksum() {
        let (mut private_key, public_key) = key_pair();
        let signature = sign(&mut private_key, b"message");

        let mut bad_version = signature.to_bytes();
        bad_version[0] = 2;
        assert!(
            public_key
                .verify(b"message", &Qhs3Signature::from_bytes(bad_version))
                .is_err()
        );

        let mut bad_checksum = signature.to_bytes();
        if let Some(byte) = bad_checksum.get_mut(QHS3_SIGNATURE_BYTES - 1) {
            *byte ^= 1;
        }
        assert!(
            public_key
                .verify(b"message", &Qhs3Signature::from_bytes(bad_checksum))
                .is_err()
        );
    }

    #[test]
    fn from_parts_rejects_out_of_range_counter() {
        assert!(Qhs3PrivateKey::from_parts([0_u8; 32], 4097).is_err());
    }

    #[test]
    fn verifies_second_leaf_and_rejects_bad_leaf_index() {
        let (mut private_key, public_key) = key_pair();
        let first = sign(&mut private_key, b"first");
        let second = sign(&mut private_key, b"second");
        assert_eq!(public_key.verify(b"first", &first), Ok(()));
        assert_eq!(public_key.verify(b"second", &second), Ok(()));
        assert_eq!(second.leaf_index(), Ok(1));

        let mut bytes = second.to_bytes();
        bytes[2..4].copy_from_slice(&4096_u16.to_le_bytes());
        assert!(
            public_key
                .verify(b"second", &Qhs3Signature::from_bytes(bytes))
                .is_err()
        );
    }

    #[test]
    fn wots_verify_rejects_wrong_length() {
        assert!(super::wots_verify(&[], &[0_u8; super::WOTS_CHAINS]).is_err());
    }

    #[test]
    fn known_answer_signature_hash() {
        let (mut private_key, _public_key) = key_pair();
        let signature = sign(&mut private_key, b"qWp QHS-3 KAT");
        assert_eq!(
            std::format!("{:?}", hash32(&signature.to_bytes())),
            "Hash32(e1c5fd67b35c6c86e0d4e9e436598e30394984db311c99392fd610f82b7ae03b)"
        );
    }

    #[test]
    fn signature_round_trip_nonzero() {
        let (mut private_key, _public_key) = key_pair();
        let signature = sign(&mut private_key, b"qWp QHS-3 round-trip");
        let bytes = signature.to_bytes();
        assert_eq!(Qhs3Signature::from_bytes(bytes).to_bytes(), bytes);
    }

    #[test]
    fn next_leaf_starts_at_zero_and_increments() {
        let (mut private_key, _public_key) = key_pair();
        assert_eq!(private_key.next_leaf(), 0);
        let _one = sign(&mut private_key, b"one");
        assert_eq!(private_key.next_leaf(), 1);
        let _two = sign(&mut private_key, b"two");
        assert_eq!(private_key.next_leaf(), 2);
    }

    #[test]
    fn public_key_metadata_mutated_one_field_at_a_time() {
        let (_, public_key) = key_pair();
        let original = public_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs3PublicKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn private_key_metadata_mutated_one_field_at_a_time() {
        let (private_key, _public_key) = key_pair();
        let original = private_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs3PrivateKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn verify_rejects_bad_algorithm_only() {
        let (mut private_key, public_key) = key_pair();
        let signature = sign(&mut private_key, b"algorithm");
        let mut bytes = signature.to_bytes();
        bytes[1] = 0;
        let body = bytes.get(..super::CHECKSUM_BODY_BYTES).unwrap();
        let checksum = super::signature_checksum(body).unwrap();
        bytes[super::CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert!(
            public_key
                .verify(b"algorithm", &Qhs3Signature::from_bytes(bytes))
                .is_err()
        );
    }
}
