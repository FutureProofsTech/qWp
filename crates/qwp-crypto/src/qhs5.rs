//! QHS-5: qWp's custom hash-based signature.
//!
//! QHS-5 is a stateful Winternitz one-time signature (WOTS) with a Merkle
//! authentication tree. It is built only on the in-tree BLAKE3 implementation.
//! The security proof is in `docs/16-qhs5.md`.

use core::fmt;
use core::mem::size_of;

use qwp_core::CryptoError;
use qwp_hash::DeriveKey64;

/// Number of base-64 message digits.
const MESSAGE_DIGITS: usize = 86;
/// Number of base-64 checksum digits.
const CHECKSUM_DIGITS: usize = 3;
/// Number of WOTS hash chains.
const WOTS_CHAINS: usize = MESSAGE_DIGITS + CHECKSUM_DIGITS;
/// Maximum WOTS chain steps.
const WOTS_CHAIN_LEN: u8 = 63;
/// Bytes in the WOTS signature.
const WOTS_SIGNATURE_BYTES: usize = WOTS_CHAINS * 64;
/// Merkle tree height.
const TREE_HEIGHT: usize = 8;
/// Number of Merkle leaves.
const LEAF_COUNT: usize = 256;
/// Bytes in a Merkle authentication path.
const AUTH_PATH_BYTES: usize = TREE_HEIGHT * 64;
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
pub const QHS5_PUBLIC_KEY_BYTES: usize = 72;
/// Private key size in bytes.
pub const QHS5_PRIVATE_KEY_BYTES: usize = 72;
/// Signature size in bytes.
pub const QHS5_SIGNATURE_BYTES: usize = CHECKSUM_OFFSET + SIGNATURE_CHECKSUM_BYTES;
/// Number of signatures available from one private key.
pub const QHS5_MAX_SIGNATURES: u16 = 256;
/// Number of Merkle leaves per key.
pub const QHS5_LEAF_COUNT: usize = LEAF_COUNT;
/// Bytes per Merkle leaf.
pub const QHS5_LEAF_BYTES: usize = 64;

const SECRET_CONTEXT: &[u8] = b"qWp QHS-5 secret";
const CHAIN_CONTEXT: &[u8] = b"qWp QHS-5 chain";
const WOTS_PK_CONTEXT: &[u8] = b"qWp QHS-5 wots-pk";
const LEAF_CONTEXT: &[u8] = b"qWp QHS-5 leaf";
const NODE_CONTEXT: &[u8] = b"qWp QHS-5 node";
const MESSAGE_CONTEXT: &[u8] = b"qWp QHS-5 message";
const CHECKSUM_CONTEXT: &[u8] = b"qWp QHS-5 signature-checksum";

/// Reusable derive-key contexts for the fixed QHS-5 domains.
struct Qhs5Contexts {
    secret: DeriveKey64,
    chain: DeriveKey64,
    wots_pk: DeriveKey64,
    leaf: DeriveKey64,
    node: DeriveKey64,
    message: DeriveKey64,
    checksum: DeriveKey64,
}

impl Qhs5Contexts {
    #[inline]
    fn new() -> Self {
        Self {
            secret: DeriveKey64::new(SECRET_CONTEXT),
            chain: DeriveKey64::new(CHAIN_CONTEXT),
            wots_pk: DeriveKey64::new(WOTS_PK_CONTEXT),
            leaf: DeriveKey64::new(LEAF_CONTEXT),
            node: DeriveKey64::new(NODE_CONTEXT),
            message: DeriveKey64::new(MESSAGE_CONTEXT),
            checksum: DeriveKey64::new(CHECKSUM_CONTEXT),
        }
    }
}

/// A QHS-5 public key: a Merkle root and algorithm metadata.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs5PublicKey {
    bytes: [u8; QHS5_PUBLIC_KEY_BYTES],
}

impl Qhs5PublicKey {
    /// Creates a public key from a Merkle root.
    #[must_use]
    #[inline]
    pub fn from_root(root: [u8; 64]) -> Self {
        let mut bytes = [0_u8; QHS5_PUBLIC_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..4) {
            slot.copy_from_slice(&[6, 6, u8::try_from(TREE_HEIGHT).unwrap_or(0), 0]);
        }
        if let Some(slot) = bytes.get_mut(4..68) {
            slot.copy_from_slice(&root);
        }
        Self { bytes }
    }

    /// Parses a public key from its exact 72-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, algorithm, height, or
    /// non-zero reserved bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS5_PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        let version = bytes.first().copied().ok_or(CryptoError::InvalidLength)?;
        let algorithm = bytes.get(1).copied().ok_or(CryptoError::InvalidLength)?;
        let height = bytes.get(2).copied().ok_or(CryptoError::InvalidLength)?;
        let reserved = bytes.get(3).copied().ok_or(CryptoError::InvalidLength)?;
        let tail = bytes.get(68..72).ok_or(CryptoError::InvalidLength)?;
        if version != 6
            || algorithm != 6
            || height != u8::try_from(TREE_HEIGHT).unwrap_or(0)
            || reserved != 0
            || tail.iter().any(|byte| *byte != 0)
        {
            return Err(CryptoError::InvalidLength);
        }
        let mut output = [0_u8; QHS5_PUBLIC_KEY_BYTES];
        output.copy_from_slice(bytes);
        Ok(Self { bytes: output })
    }

    /// Returns the exact 72-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS5_PUBLIC_KEY_BYTES] {
        self.bytes
    }

    /// Returns the Merkle root.
    #[must_use]
    #[inline]
    pub fn root(&self) -> [u8; 64] {
        let mut root = [0_u8; 64];
        if let Some(slot) = self.bytes.get(4..68) {
            root.copy_from_slice(slot);
        }
        root
    }

    /// Verifies a QHS-5 signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerificationFailed`] for an invalid signature.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &Qhs5Signature) -> Result<(), CryptoError> {
        let bytes = signature.as_bytes();
        if bytes.first() != Some(&6) || bytes.get(1) != Some(&6) {
            return Err(CryptoError::VerificationFailed);
        }
        let leaf_bytes = bytes.get(2..4).ok_or(CryptoError::VerificationFailed)?;
        let mut leaf_word = [0_u8; 2];
        leaf_word.copy_from_slice(leaf_bytes);
        let leaf_index = u16::from_le_bytes(leaf_word);
        if leaf_index >= QHS5_MAX_SIGNATURES {
            return Err(CryptoError::VerificationFailed);
        }

        let body = bytes
            .get(..CHECKSUM_BODY_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let contexts = Qhs5Contexts::new();
        let expected_checksum = signature_checksum(body, &contexts)?;
        let actual_checksum = bytes
            .get(CHECKSUM_OFFSET..QHS5_SIGNATURE_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        if actual_checksum != expected_checksum {
            return Err(CryptoError::VerificationFailed);
        }

        let digits = message_digits(message, &contexts);
        let wots_signature = bytes
            .get(WOTS_OFFSET..AUTH_OFFSET)
            .ok_or(CryptoError::VerificationFailed)?;
        let wots_pk_hash = wots_verify(wots_signature, &digits, &contexts)?;
        let mut node = leaf_hash(leaf_index, &wots_pk_hash, &contexts);
        let auth_path = bytes
            .get(AUTH_OFFSET..CHECKSUM_OFFSET)
            .ok_or(CryptoError::VerificationFailed)?;

        for (level, sibling) in auth_path.as_chunks::<64>().0.iter().enumerate() {
            let level_u32 = u32::try_from(level).unwrap_or(0);
            let bit = leaf_index.checked_shr(level_u32).unwrap_or(0) & 1;
            if bit == 0 {
                node = node_hash(&node, sibling, &contexts);
            } else {
                node = node_hash(sibling, &node, &contexts);
            }
        }

        if node == self.root() {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// A QHS-5 private key.
///
/// The key is stateful: each signature consumes one Merkle leaf. It is not
/// `Clone`, is not printable, and is wiped best-effort on drop.
pub struct Qhs5PrivateKey {
    seed: [u8; 64],
    next_leaf: u16,
    reserved: [u8; 6],
}

impl Qhs5PrivateKey {
    /// Creates a private key from a seed and a starting leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if `next_leaf` exceeds [`QHS5_MAX_SIGNATURES`].
    #[inline]
    pub const fn from_parts(seed: [u8; 64], next_leaf: u16) -> Result<Self, CryptoError> {
        if next_leaf > QHS5_MAX_SIGNATURES {
            return Err(CryptoError::InvalidLength);
        }
        Ok(Self {
            seed,
            next_leaf,
            reserved: [0; 6],
        })
    }

    /// Parses a private key from its exact 72-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata or an out-of-range leaf counter.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS5_PRIVATE_KEY_BYTES]) -> Result<Self, CryptoError> {
        let version = bytes.first().copied().ok_or(CryptoError::InvalidLength)?;
        let algorithm = bytes.get(1).copied().ok_or(CryptoError::InvalidLength)?;
        let height = bytes.get(2).copied().ok_or(CryptoError::InvalidLength)?;
        let reserved = bytes.get(3).copied().ok_or(CryptoError::InvalidLength)?;
        if version != 6
            || algorithm != 6
            || height != u8::try_from(TREE_HEIGHT).unwrap_or(0)
            || reserved != 0
        {
            return Err(CryptoError::InvalidLength);
        }
        let seed_slice = bytes.get(4..68).ok_or(CryptoError::InvalidLength)?;
        let mut seed = [0_u8; 64];
        seed.copy_from_slice(seed_slice);
        let counter_slice = bytes.get(68..70).ok_or(CryptoError::InvalidLength)?;
        let mut counter_word = [0_u8; 2];
        counter_word.copy_from_slice(counter_slice);
        let next_leaf = u16::from_le_bytes(counter_word);
        let reserved_tail = bytes.get(70..72).ok_or(CryptoError::InvalidLength)?;
        if reserved_tail.iter().any(|byte| *byte != 0) {
            return Err(CryptoError::InvalidPadding);
        }
        Self::from_parts(seed, next_leaf)
    }

    /// Serializes the private key into its exact 72-byte representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; QHS5_PRIVATE_KEY_BYTES] {
        let mut bytes = [0_u8; QHS5_PRIVATE_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..4) {
            slot.copy_from_slice(&[6, 6, u8::try_from(TREE_HEIGHT).unwrap_or(0), 0]);
        }
        if let Some(slot) = bytes.get_mut(4..68) {
            slot.copy_from_slice(&self.seed);
        }
        if let Some(slot) = bytes.get_mut(68..70) {
            slot.copy_from_slice(&self.next_leaf.to_le_bytes());
        }
        if let Some(slot) = bytes.get_mut(70..72) {
            slot.copy_from_slice(&self.reserved[..2]);
        }
        bytes
    }

    /// Returns the secret seed for host-side leaf derivation.
    ///
    /// The caller must not log or expose this value.
    #[must_use]
    #[inline]
    pub const fn seed(&self) -> &[u8; 64] {
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
        self.next_leaf >= QHS5_MAX_SIGNATURES
    }

    /// Signs a message and consumes one Merkle leaf.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 256 signatures.
    #[inline]
    pub fn sign(&mut self, message: &[u8]) -> Result<Qhs5Signature, CryptoError> {
        if self.is_exhausted() {
            return Err(CryptoError::KeyExhausted);
        }
        let contexts = Qhs5Contexts::new();
        let leaves = compute_leaves(&self.seed, &contexts)?;
        self.sign_with_leaves_contexts(message, &leaves, &contexts)
    }

    /// Signs a message using precomputed Merkle leaves.
    ///
    /// The leaves must be the exact leaves derived from this key's seed. The
    /// CLI validates a fingerprinted cache before calling this. Caching is a
    /// performance optimization only; it does not change the signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyExhausted`] after 256 signatures.
    #[inline]
    pub fn sign_with_leaves(
        &mut self,
        message: &[u8],
        leaves: &[[u8; 64]; LEAF_COUNT],
    ) -> Result<Qhs5Signature, CryptoError> {
        let contexts = Qhs5Contexts::new();
        self.sign_with_leaves_contexts(message, leaves, &contexts)
    }

    fn sign_with_leaves_contexts(
        &mut self,
        message: &[u8],
        leaves: &[[u8; 64]; LEAF_COUNT],
        contexts: &Qhs5Contexts,
    ) -> Result<Qhs5Signature, CryptoError> {
        if self.is_exhausted() {
            return Err(CryptoError::KeyExhausted);
        }
        let leaf_index = self.next_leaf;
        self.next_leaf = self.next_leaf.saturating_add(1);

        let digits = message_digits(message, contexts);
        let wots_signature = wots_sign(&self.seed, leaf_index, &digits, contexts)?;
        let auth_path = auth_path_from_leaves(leaves, leaf_index, contexts)?;
        build_signature(leaf_index, &wots_signature, &auth_path, contexts)
    }
}

fn build_signature(
    leaf_index: u16,
    wots_signature: &[u8; WOTS_SIGNATURE_BYTES],
    auth_path: &[[u8; 64]; TREE_HEIGHT],
    contexts: &Qhs5Contexts,
) -> Result<Qhs5Signature, CryptoError> {
    let mut bytes = [0_u8; QHS5_SIGNATURE_BYTES];

    if let Some(slot) = bytes.get_mut(0..4) {
        slot.copy_from_slice(&[6, 6, 0, 0]);
    }
    if let Some(slot) = bytes.get_mut(2..4) {
        slot.copy_from_slice(&leaf_index.to_le_bytes());
    }
    if let Some(slot) = bytes.get_mut(WOTS_OFFSET..AUTH_OFFSET) {
        slot.copy_from_slice(wots_signature);
    }
    if let Some(slot) = bytes.get_mut(AUTH_OFFSET..CHECKSUM_OFFSET) {
        for (destination, source) in slot
            .as_chunks_mut::<64>()
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
    let checksum = signature_checksum(body, contexts)?;
    if let Some(slot) = bytes.get_mut(CHECKSUM_OFFSET..QHS5_SIGNATURE_BYTES) {
        slot.copy_from_slice(&checksum);
    }

    Ok(Qhs5Signature { bytes })
}

impl Drop for Qhs5PrivateKey {
    #[inline]
    fn drop(&mut self) {
        self.seed.fill(0);
        self.next_leaf = 0;
    }
}

impl fmt::Debug for Qhs5PrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Qhs5PrivateKey")
            .field("next_leaf", &self.next_leaf)
            .finish_non_exhaustive()
    }
}

/// A QHS-5 signature.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs5Signature {
    bytes: [u8; QHS5_SIGNATURE_BYTES],
}

impl Qhs5Signature {
    /// Creates a signature from its exact 6,216-byte representation.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; QHS5_SIGNATURE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Returns the exact 6,216-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS5_SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; QHS5_SIGNATURE_BYTES] {
        &self.bytes
    }

    /// Parses a signature from a byte slice of exactly 6,216 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] for any other length.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let source = <[u8; QHS5_SIGNATURE_BYTES]>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self { bytes: source })
    }

    /// Returns the signature bytes as a slice.
    #[must_use]
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
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
pub fn qhs5_leaf(seed: &[u8; 64], leaf_index: u16) -> Result<[u8; 64], CryptoError> {
    let contexts = Qhs5Contexts::new();
    qhs5_leaf_with_contexts(seed, leaf_index, &contexts)
}

fn qhs5_leaf_with_contexts(
    seed: &[u8; 64],
    leaf_index: u16,
    contexts: &Qhs5Contexts,
) -> Result<[u8; 64], CryptoError> {
    if leaf_index >= QHS5_MAX_SIGNATURES {
        return Err(CryptoError::InvalidLength);
    }
    let wots_pk = wots_pk_hash(seed, leaf_index, contexts);
    Ok(leaf_hash(leaf_index, &wots_pk, contexts))
}

/// Computes all Merkle leaves from the seed.
///
/// # Errors
///
/// Returns an internal length error if a fixed-size buffer is malformed.
#[inline]
pub fn qhs5_leaves(seed: &[u8; 64]) -> Result<[[u8; 64]; LEAF_COUNT], CryptoError> {
    let contexts = Qhs5Contexts::new();
    compute_leaves(seed, &contexts)
}

/// Builds a key pair from precomputed Merkle leaves.
///
/// The leaves must be the exact leaves derived from `seed`. This is a
/// performance API used by the host key store after cache validation.
///
/// # Errors
///
/// Returns an internal length error if a fixed-size buffer is malformed.
#[inline]
pub fn qhs5_keygen_from_leaves(
    seed: &[u8; 64],
    leaves: &[[u8; 64]; LEAF_COUNT],
) -> Result<(Qhs5PrivateKey, Qhs5PublicKey), CryptoError> {
    let contexts = Qhs5Contexts::new();
    qhs5_keygen_from_leaves_with_contexts(seed, leaves, &contexts)
}

fn qhs5_keygen_from_leaves_with_contexts(
    seed: &[u8; 64],
    leaves: &[[u8; 64]; LEAF_COUNT],
    contexts: &Qhs5Contexts,
) -> Result<(Qhs5PrivateKey, Qhs5PublicKey), CryptoError> {
    let root = merkle_root(*leaves, contexts)?;
    let private_key = Qhs5PrivateKey::from_parts(*seed, 0)?;
    let public_key = Qhs5PublicKey::from_root(root);
    Ok((private_key, public_key))
}

/// Generates a QHS-5 key pair from a 64-byte seed.
///
/// # Errors
///
/// Returns an internal length error if a fixed-size buffer is malformed.
#[inline]
pub fn keygen(seed: &[u8; 64]) -> Result<(Qhs5PrivateKey, Qhs5PublicKey), CryptoError> {
    let contexts = Qhs5Contexts::new();
    let leaves = compute_leaves(seed, &contexts)?;
    qhs5_keygen_from_leaves_with_contexts(seed, &leaves, &contexts)
}

fn secret(seed: &[u8; 64], leaf_index: u16, chain_index: u8, contexts: &Qhs5Contexts) -> [u8; 64] {
    let mut hasher = contexts.secret.hasher();
    hasher.update(seed);
    hasher.update(&leaf_index.to_le_bytes());
    hasher.update(&[chain_index]);
    hasher.finalize().to_bytes()
}

fn chain_hash(value: &[u8; 64], contexts: &Qhs5Contexts) -> [u8; 64] {
    contexts.chain.hash64(value).to_bytes()
}

fn wots_pk_hash(seed: &[u8; 64], leaf_index: u16, contexts: &Qhs5Contexts) -> [u8; 64] {
    let mut hasher = contexts.wots_pk.hasher();
    for chain_index in 0..WOTS_CHAINS {
        let chain_u8 = u8::try_from(chain_index).unwrap_or(0);
        let mut value = secret(seed, leaf_index, chain_u8, contexts);
        for _ in 0..WOTS_CHAIN_LEN {
            value = chain_hash(&value, contexts);
        }
        hasher.update(&value);
    }
    hasher.finalize().to_bytes()
}

fn leaf_hash(leaf_index: u16, wots_pk: &[u8; 64], contexts: &Qhs5Contexts) -> [u8; 64] {
    let mut input = [0_u8; 66];
    if let Some(slot) = input.get_mut(0..2) {
        slot.copy_from_slice(&leaf_index.to_le_bytes());
    }
    if let Some(slot) = input.get_mut(2..66) {
        slot.copy_from_slice(wots_pk);
    }
    contexts.leaf.hash64(&input).to_bytes()
}

fn node_hash(left: &[u8; 64], right: &[u8; 64], contexts: &Qhs5Contexts) -> [u8; 64] {
    let mut input = [0_u8; 128];
    if let Some(slot) = input.get_mut(0..64) {
        slot.copy_from_slice(left);
    }
    if let Some(slot) = input.get_mut(64..128) {
        slot.copy_from_slice(right);
    }
    contexts.node.hash64(&input).to_bytes()
}

fn compute_leaves(
    seed: &[u8; 64],
    contexts: &Qhs5Contexts,
) -> Result<[[u8; 64]; LEAF_COUNT], CryptoError> {
    let mut leaves = [[0_u8; 64]; LEAF_COUNT];
    for (index, slot) in leaves.iter_mut().enumerate() {
        let leaf_index = u16::try_from(index).map_err(|_| CryptoError::InvalidLength)?;
        let wots_pk = wots_pk_hash(seed, leaf_index, contexts);
        *slot = leaf_hash(leaf_index, &wots_pk, contexts);
    }
    Ok(leaves)
}

fn merkle_root(
    mut nodes: [[u8; 64]; LEAF_COUNT],
    contexts: &Qhs5Contexts,
) -> Result<[u8; 64], CryptoError> {
    let mut count = LEAF_COUNT;
    while count > 1 {
        let half = count.checked_shr(1).unwrap_or(0);
        for index in 0..half {
            let left_index = index.checked_mul(2).unwrap_or(0);
            let right_index = left_index.checked_add(1).unwrap_or(0);
            let left = *nodes.get(left_index).ok_or(CryptoError::InvalidLength)?;
            let right = *nodes.get(right_index).ok_or(CryptoError::InvalidLength)?;
            let parent = node_hash(&left, &right, contexts);
            if let Some(slot) = nodes.get_mut(index) {
                *slot = parent;
            }
        }
        count = half;
    }
    nodes.first().copied().ok_or(CryptoError::InvalidLength)
}

fn auth_path_from_leaves(
    leaves: &[[u8; 64]; LEAF_COUNT],
    leaf_index: u16,
    contexts: &Qhs5Contexts,
) -> Result<[[u8; 64]; TREE_HEIGHT], CryptoError> {
    let mut nodes = *leaves;
    let mut path = [[0_u8; 64]; TREE_HEIGHT];
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
            let parent = node_hash(&left, &right, contexts);
            if let Some(slot) = nodes.get_mut(index) {
                *slot = parent;
            }
        }
        count = half;
    }

    Ok(path)
}

fn message_digits(message: &[u8], contexts: &Qhs5Contexts) -> [u8; WOTS_CHAINS] {
    let digest = contexts.message.hash64(message).to_bytes();
    let mut digits = [0_u8; WOTS_CHAINS];

    // 86 base-64 digits encode the 512-bit digest with four leading zero bits.
    for index in 0..MESSAGE_DIGITS {
        let mut value = 0_u8;
        for offset in 0..6 {
            let padded_bit = index
                .checked_mul(6)
                .unwrap_or(0)
                .checked_add(offset)
                .unwrap_or(0);
            let bit = if padded_bit < 4 {
                0
            } else {
                let digest_bit = padded_bit.saturating_sub(4);
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

    // Three base-64 checksum digits encode the value in 0..=5418.
    let mut checksum = 0_u16;
    for digit in digits.iter().take(MESSAGE_DIGITS) {
        checksum = checksum.wrapping_add(63_u16.saturating_sub(u16::from(*digit)));
    }
    if let Some(slot) = digits.get_mut(MESSAGE_DIGITS) {
        *slot = u8::try_from(checksum.wrapping_shr(12)).unwrap_or(0);
    }
    if let Some(slot) = digits.get_mut(MESSAGE_DIGITS.checked_add(1).unwrap_or(0)) {
        *slot = u8::try_from(checksum.wrapping_shr(6) & 0x3f).unwrap_or(0);
    }
    if let Some(slot) = digits.get_mut(MESSAGE_DIGITS.checked_add(2).unwrap_or(0)) {
        *slot = u8::try_from(checksum & 0x3f).unwrap_or(0);
    }
    digits
}

fn wots_sign(
    seed: &[u8; 64],
    leaf_index: u16,
    digits: &[u8; WOTS_CHAINS],
    contexts: &Qhs5Contexts,
) -> Result<[u8; WOTS_SIGNATURE_BYTES], CryptoError> {
    let mut signature = [0_u8; WOTS_SIGNATURE_BYTES];
    for (chain_index, (slot, digit)) in signature
        .as_chunks_mut::<64>()
        .0
        .iter_mut()
        .zip(digits.iter())
        .enumerate()
    {
        let chain_u8 = u8::try_from(chain_index).map_err(|_| CryptoError::InvalidLength)?;
        let mut value = secret(seed, leaf_index, chain_u8, contexts);
        for _ in 0..*digit {
            value = chain_hash(&value, contexts);
        }
        slot.copy_from_slice(&value);
    }
    Ok(signature)
}

fn wots_verify(
    signature: &[u8],
    digits: &[u8; WOTS_CHAINS],
    contexts: &Qhs5Contexts,
) -> Result<[u8; 64], CryptoError> {
    if signature.len() != WOTS_SIGNATURE_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let mut hasher = contexts.wots_pk.hasher();
    for (slot, digit) in signature.as_chunks::<64>().0.iter().zip(digits.iter()) {
        let mut value = [0_u8; 64];
        value.copy_from_slice(slot);
        let steps = WOTS_CHAIN_LEN.saturating_sub(*digit);
        for _ in 0..steps {
            value = chain_hash(&value, contexts);
        }
        hasher.update(&value);
    }
    Ok(hasher.finalize().to_bytes())
}

fn signature_checksum(
    body: &[u8],
    contexts: &Qhs5Contexts,
) -> Result<[u8; SIGNATURE_CHECKSUM_BYTES], CryptoError> {
    let hash = contexts.checksum.hash64(body);
    let mut checksum = [0_u8; SIGNATURE_CHECKSUM_BYTES];
    let source = hash
        .as_bytes()
        .get(..SIGNATURE_CHECKSUM_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    checksum.copy_from_slice(source);
    Ok(checksum)
}

const _: [(); QHS5_PUBLIC_KEY_BYTES] = [(); size_of::<Qhs5PublicKey>()];
const _: [(); QHS5_SIGNATURE_BYTES] = [(); size_of::<Qhs5Signature>()];
const _: [(); QHS5_PRIVATE_KEY_BYTES] = [(); size_of::<Qhs5PrivateKey>()];
const _: [(); 6216] = [(); QHS5_SIGNATURE_BYTES];

#[cfg(test)]
mod tests {
    use super::{
        CHAIN_CONTEXT, CHECKSUM_CONTEXT, LEAF_CONTEXT, MESSAGE_CONTEXT, MESSAGE_DIGITS,
        NODE_CONTEXT, QHS5_MAX_SIGNATURES, QHS5_SIGNATURE_BYTES, Qhs5Contexts, Qhs5PrivateKey,
        Qhs5PublicKey, Qhs5Signature, SECRET_CONTEXT, WOTS_CHAINS, WOTS_PK_CONTEXT, keygen,
        qhs5_keygen_from_leaves, qhs5_leaf, qhs5_leaves,
    };
    use core::mem::size_of;
    use qwp_core::CryptoError;
    use qwp_hash::{derive_key64, hash32};

    const SEED: [u8; 64] = [7_u8; 64];

    #[test]
    fn sign_verify_round_trip() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"qWp QHS-5 message").unwrap();
        assert_eq!(public_key.verify(b"qWp QHS-5 message", &signature), Ok(()));
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
        let tampered = Qhs5Signature::from_bytes(bytes);
        assert_eq!(
            public_key.verify(b"message", &tampered),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let (mut private_key, _public_key) = keygen(&SEED).unwrap();
        let (_, other_public_key) = keygen(&[9_u8; 64]).unwrap();
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
        bytes[68..70].copy_from_slice(&QHS5_MAX_SIGNATURES.to_le_bytes());
        let mut exhausted = Qhs5PrivateKey::from_bytes(&bytes).unwrap();
        assert!(exhausted.is_exhausted());
        assert_eq!(exhausted.sign(b"message"), Err(CryptoError::KeyExhausted));
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let (private_key, _public_key) = keygen(&SEED).unwrap();
        let debug = std::format!("{private_key:?}");
        assert!(debug.contains("Qhs5PrivateKey"));
        assert!(!debug.contains("seed"));
    }

    #[test]
    fn private_key_seed_accessor_matches() {
        let (private_key, _public_key) = keygen(&SEED).unwrap();
        assert_eq!(private_key.seed(), &SEED);
    }

    #[test]
    fn sign_with_leaves_rejects_exhausted_key() {
        let leaves = qhs5_leaves(&SEED).unwrap();
        let mut exhausted = Qhs5PrivateKey::from_parts(SEED, QHS5_MAX_SIGNATURES).unwrap();
        assert_eq!(
            exhausted.sign_with_leaves(b"message", &leaves),
            Err(CryptoError::KeyExhausted)
        );
    }

    #[test]
    fn signature_slice_round_trip_and_length_check() {
        let (mut private_key, _public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"slice").unwrap();
        assert_eq!(
            Qhs5Signature::from_slice(signature.as_slice()),
            Ok(signature)
        );
        assert_eq!(signature.as_slice(), &signature.to_bytes()[..]);
        assert_eq!(
            Qhs5Signature::from_slice(&signature.as_slice()[..100]),
            Err(CryptoError::InvalidLength)
        );
    }

    #[test]
    fn leaf_rejects_out_of_range_index() {
        assert_eq!(
            qhs5_leaf(&SEED, QHS5_MAX_SIGNATURES),
            Err(CryptoError::InvalidLength)
        );
    }

    #[test]
    fn signature_size_is_exact() {
        assert_eq!(size_of::<Qhs5Signature>(), QHS5_SIGNATURE_BYTES);
        assert_eq!(QHS5_SIGNATURE_BYTES, 6216);
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

    #[test]
    fn cached_leaves_match_sequential_keygen_and_sign() {
        let leaves = qhs5_leaves(&SEED).unwrap();
        assert_eq!(qhs5_leaf(&SEED, 0).unwrap(), leaves[0]);

        let (mut sequential_key, sequential_public) = keygen(&SEED).unwrap();
        let (mut cached_key, cached_public) = qhs5_keygen_from_leaves(&SEED, &leaves).unwrap();
        assert_eq!(sequential_public, cached_public);

        let sequential_signature = sequential_key.sign(b"cached").unwrap();
        let cached_signature = cached_key.sign_with_leaves(b"cached", &leaves).unwrap();
        assert_eq!(sequential_signature, cached_signature);
        assert_eq!(cached_public.verify(b"cached", &cached_signature), Ok(()));
    }

    #[test]
    fn public_key_round_trip() {
        let (_, public_key) = keygen(&SEED).unwrap();
        let bytes = public_key.to_bytes();
        assert_eq!(Qhs5PublicKey::from_bytes(&bytes), Ok(public_key));
    }

    #[test]
    fn public_key_rejects_bad_metadata() {
        let mut bytes = [0_u8; super::QHS5_PUBLIC_KEY_BYTES];
        bytes[0] = 0;
        assert!(Qhs5PublicKey::from_bytes(&bytes).is_err());
        bytes[0] = 1;
        bytes[1] = 0;
        assert!(Qhs5PublicKey::from_bytes(&bytes).is_err());
        bytes[1] = 1;
        bytes[2] = 0;
        assert!(Qhs5PublicKey::from_bytes(&bytes).is_err());
        bytes[2] = 8;
        bytes[3] = 1;
        assert!(Qhs5PublicKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn private_key_rejects_bad_metadata_and_counter() {
        let mut bytes = [0_u8; super::QHS5_PRIVATE_KEY_BYTES];
        bytes[0] = 0;
        assert!(Qhs5PrivateKey::from_bytes(&bytes).is_err());
        bytes[0] = 6;
        bytes[1] = 5;
        bytes[2] = 8;
        bytes[3] = 0;
        assert!(Qhs5PrivateKey::from_bytes(&bytes).is_err());
        bytes[1] = 6;
        bytes[70] = 1;
        assert!(Qhs5PrivateKey::from_bytes(&bytes).is_err());
        bytes[70] = 0;
        bytes[68..70].copy_from_slice(&257_u16.to_le_bytes());
        assert!(Qhs5PrivateKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn signature_rejects_bad_version_and_checksum() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"message").unwrap();

        let mut bad_version = signature.to_bytes();
        bad_version[0] = 0;
        assert!(
            public_key
                .verify(b"message", &Qhs5Signature::from_bytes(bad_version))
                .is_err()
        );

        let mut bad_checksum = signature.to_bytes();
        if let Some(byte) = bad_checksum.get_mut(QHS5_SIGNATURE_BYTES - 1) {
            *byte ^= 1;
        }
        assert!(
            public_key
                .verify(b"message", &Qhs5Signature::from_bytes(bad_checksum))
                .is_err()
        );
    }

    #[test]
    fn from_parts_rejects_out_of_range_counter() {
        assert!(Qhs5PrivateKey::from_parts([0_u8; 64], 257).is_err());
    }

    #[test]
    fn verifies_second_leaf_and_rejects_bad_leaf_index() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        let first = private_key.sign(b"first").unwrap();
        let second = private_key.sign(b"second").unwrap();
        assert_eq!(public_key.verify(b"first", &first), Ok(()));
        assert_eq!(public_key.verify(b"second", &second), Ok(()));
        assert_eq!(second.leaf_index(), Ok(1));

        let mut bytes = second.to_bytes();
        bytes[2..4].copy_from_slice(&256_u16.to_le_bytes());
        assert!(
            public_key
                .verify(b"second", &Qhs5Signature::from_bytes(bytes))
                .is_err()
        );
    }

    #[test]
    fn wots_verify_rejects_wrong_length() {
        let contexts = Qhs5Contexts::new();
        assert!(super::wots_verify(&[], &[0_u8; WOTS_CHAINS], &contexts).is_err());
    }

    #[test]
    fn message_digits_leading_zero_bits_are_enforced() {
        let mut message = [0_u8; 8];
        let mut found = false;
        let contexts = Qhs5Contexts::new();
        for counter in 0..1024_u32 {
            message[..4].copy_from_slice(&counter.to_le_bytes());
            let digest = derive_key64(MESSAGE_CONTEXT, &message).to_bytes();
            if digest[0] & 0x80 != 0 {
                let digits = super::message_digits(&message, &contexts);
                assert!(digits[0] < 16);
                assert_eq!(digits[0], digest[0] >> 6);
                assert_eq!(digits[1], digest[0] & 0x3f);
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[test]
    fn message_digits_shape_and_checksum() {
        let message = b"qWp QHS-5 512-bit digit encoding";
        let digest = derive_key64(MESSAGE_CONTEXT, message).to_bytes();
        let contexts = Qhs5Contexts::new();
        let digits = super::message_digits(message, &contexts);
        assert_eq!(digits.len(), WOTS_CHAINS);
        assert!(digits.first().is_some_and(|digit| *digit < 16));

        let mut reconstructed = [0_u8; 64];
        for (index, digit) in digits.iter().take(MESSAGE_DIGITS).enumerate() {
            let digit = *digit;
            for offset in 0..6 {
                let padded_bit = index * 6 + offset;
                let bit = (digit >> (5 - offset)) & 1;
                if padded_bit < 4 {
                    assert_eq!(bit, 0);
                } else {
                    let digest_bit = padded_bit - 4;
                    reconstructed[digest_bit / 8] |= bit << (7 - (digest_bit % 8));
                }
            }
        }
        assert_eq!(reconstructed, digest);

        let mut checksum = 0_u16;
        for digit in digits.iter().take(MESSAGE_DIGITS) {
            checksum += 63_u16 - u16::from(*digit);
        }
        assert_eq!(
            digits.get(MESSAGE_DIGITS),
            Some(&u8::try_from(checksum >> 12).unwrap())
        );
        assert_eq!(
            digits.get(MESSAGE_DIGITS + 1),
            Some(&u8::try_from((checksum >> 6) & 0x3f).unwrap())
        );
        assert_eq!(
            digits.get(MESSAGE_DIGITS + 2),
            Some(&u8::try_from(checksum & 0x3f).unwrap())
        );
    }

    #[test]
    fn key_and_signature_headers_are_exact() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        assert_eq!(&public_key.to_bytes()[..4], &[6, 6, 8, 0]);
        assert_eq!(&private_key.to_bytes()[..4], &[6, 6, 8, 0]);
        let signature = private_key.sign(b"header").unwrap();
        assert_eq!(&signature.to_bytes()[..4], &[6, 6, 0, 0]);
        let signature = private_key.sign(b"header").unwrap();
        assert_eq!(&signature.to_bytes()[..4], &[6, 6, 1, 0]);
    }

    #[test]
    fn known_answer_signature_hash() {
        let (mut private_key, _public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"qWp QHS-5 KAT").unwrap();
        assert_eq!(
            std::format!("{:?}", hash32(&signature.to_bytes())),
            "Hash32(104c828b2172442e32d3ffe8448a9d6358b4a48fe7573a6a7367ec5986d6aada)"
        );
    }

    #[test]
    fn signature_round_trip_nonzero() {
        let (mut private_key, _public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"qWp QHS-5 round-trip").unwrap();
        let bytes = signature.to_bytes();
        assert_eq!(Qhs5Signature::from_bytes(bytes).to_bytes(), bytes);
    }

    #[test]
    fn next_leaf_starts_at_zero_and_increments() {
        let (mut private_key, _public_key) = keygen(&SEED).unwrap();
        assert_eq!(private_key.next_leaf(), 0);
        let _one = private_key.sign(b"one").unwrap();
        assert_eq!(private_key.next_leaf(), 1);
        let _two = private_key.sign(b"two").unwrap();
        assert_eq!(private_key.next_leaf(), 2);
    }

    #[test]
    fn public_key_metadata_mutated_one_field_at_a_time() {
        let (_, public_key) = keygen(&SEED).unwrap();
        let original = public_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs5PublicKey::from_bytes(&bytes).is_err());
        }
        for index in 68..72 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs5PublicKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn private_key_metadata_mutated_one_field_at_a_time() {
        let (private_key, _public_key) = keygen(&SEED).unwrap();
        let original = private_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs5PrivateKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn verify_rejects_bad_algorithm_only() {
        let (mut private_key, public_key) = keygen(&SEED).unwrap();
        let signature = private_key.sign(b"algorithm").unwrap();
        let mut bytes = signature.to_bytes();
        bytes[1] = 0;
        let body = bytes.get(..super::CHECKSUM_BODY_BYTES).unwrap();
        let contexts = Qhs5Contexts::new();
        let checksum = super::signature_checksum(body, &contexts).unwrap();
        bytes[super::CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        assert!(
            public_key
                .verify(b"algorithm", &Qhs5Signature::from_bytes(bytes))
                .is_err()
        );
    }
}
