//! QHS-4.2: stateless hypertree/FORS signature.
//!
//! QHS-4.2 uses a FORS few-time signature at the bottom of an 8-layer hypertree
//! of WOTS keys. It has no state counter and no cache. The proof is in
//! `docs/13-qhs42.md`.

use core::fmt;
use core::mem::size_of;

use qwp_core::CryptoError;
use qwp_hash::{DeriveKey, Hasher, derive_key32};

/// Number of base-64 message digits.
const MESSAGE_DIGITS: usize = 32;
/// Number of base-64 checksum digits.
const CHECKSUM_DIGITS: usize = 2;
/// Number of WOTS hash chains.
const WOTS_CHAINS: usize = MESSAGE_DIGITS + CHECKSUM_DIGITS;
/// Maximum WOTS chain steps.
const WOTS_CHAIN_LEN: u8 = 255;
/// Bytes in a WOTS signature.
const WOTS_SIGNATURE_BYTES: usize = WOTS_CHAINS * 32;
/// Hypertree subtree height.
const TREE_HEIGHT: usize = 8;
/// Number of leaves in a hypertree subtree.
const LEAF_COUNT: usize = 256;
/// Bytes in a subtree authentication path.
const AUTH_PATH_BYTES: usize = TREE_HEIGHT * 32;
/// Number of hypertree layers.
const LAYERS: usize = 7;
/// Total hypertree height.
const TOTAL_HEIGHT: usize = 56;
/// Number of FORS trees.
const FORS_TREES: usize = 17;
/// FORS tree height.
const FORS_HEIGHT: usize = 8;
/// Number of FORS leaves per tree.
const FORS_LEAVES: usize = 256;
/// Bytes in one FORS authentication path.
const FORS_AUTH_BYTES: usize = FORS_HEIGHT * 32;
/// Bytes in one FORS secret.
const FORS_SECRET_BYTES: usize = 32;
/// Bytes in one FORS tree signature.
const FORS_ENTRY_BYTES: usize = FORS_SECRET_BYTES + FORS_AUTH_BYTES;
/// Bytes in the FORS signature.
const FORS_SIGNATURE_BYTES: usize = FORS_TREES * FORS_ENTRY_BYTES;
/// Signature header bytes.
const HEADER_BYTES: usize = 4;
/// Randomizer bytes.
const RANDOMIZER_BYTES: usize = 32;
/// Signature checksum bytes.
const CHECKSUM_BYTES: usize = 4;
/// Offset of the randomizer.
const RANDOMIZER_OFFSET: usize = HEADER_BYTES;
/// Offset of the FORS signature.
const FORS_OFFSET: usize = HEADER_BYTES + RANDOMIZER_BYTES;
/// Bytes in one hypertree layer signature.
const LAYER_BYTES: usize = WOTS_SIGNATURE_BYTES + AUTH_PATH_BYTES;
/// Offset of the hypertree layers.
const LAYER_OFFSET: usize = FORS_OFFSET + FORS_SIGNATURE_BYTES;
/// Offset of the signature checksum.
const CHECKSUM_OFFSET: usize = LAYER_OFFSET + LAYERS * LAYER_BYTES;
/// Bytes covered by the signature checksum.
const CHECKSUM_BODY_BYTES: usize = CHECKSUM_OFFSET;
/// Fixed key and signature header: version, algorithm, height, reserved.
const KEY_HEADER: [u8; HEADER_BYTES] = [5, 5, 56, 0];

/// QHS-4.2 public key size.
pub const QHS42_PUBLIC_KEY_BYTES: usize = 68;
/// QHS-4.2 private key size.
pub const QHS42_PRIVATE_KEY_BYTES: usize = 68;
/// QHS-4.2 signature size.
pub const QHS42_SIGNATURE_BYTES: usize = CHECKSUM_OFFSET + CHECKSUM_BYTES;
/// QHS-4.2 total hypertree height.
pub const QHS42_TOTAL_HEIGHT: usize = TOTAL_HEIGHT;
/// QHS-4.2 FORS signature size.
pub const QHS42_FORS_BYTES: usize = FORS_SIGNATURE_BYTES;
/// QHS-4.2 hypertree layers.
pub const QHS42_LAYERS: usize = LAYERS;
/// QHS-4.2 leaves per hypertree subtree.
pub const QHS42_LEAF_COUNT: usize = LEAF_COUNT;
/// QHS-4.2 hypertree subtree height.
pub const QHS42_TREE_HEIGHT: usize = TREE_HEIGHT;
/// QHS-4.2 FORS trees.
pub const QHS42_FORS_TREES: usize = FORS_TREES;
/// QHS-4.2 FORS leaves per tree.
pub const QHS42_FORS_LEAVES: usize = FORS_LEAVES;
/// QHS-4.2 FORS tree height.
pub const QHS42_FORS_HEIGHT: usize = FORS_HEIGHT;

const SK_SEED_CONTEXT: &[u8] = b"qWp QHS-4.2 sk seed";
const PK_SEED_CONTEXT: &[u8] = b"qWp QHS-4.2 pk seed";
const RANDOMIZER_CONTEXT: &[u8] = b"qWp QHS-4.2 randomizer";
const FORS_DIGEST_CONTEXT: &[u8] = b"qWp QHS-4.2 fors digest";
const TREE_INDEX_CONTEXT: &[u8] = b"qWp QHS-4.2 tree index";
const WOTS_SECRET_CONTEXT: &[u8] = b"qWp QHS-4.2 wots secret";
const CHAIN_CONTEXT: &[u8] = b"qWp QHS-4.2 chain";
const WOTS_MESSAGE_CONTEXT: &[u8] = b"qWp QHS-4.2 wots message";
const WOTS_PK_CONTEXT: &[u8] = b"qWp QHS-4.2 wots-pk";
const LEAF_CONTEXT: &[u8] = b"qWp QHS-4.2 leaf";
const NODE_CONTEXT: &[u8] = b"qWp QHS-4.2 node";
const FORS_SECRET_CONTEXT: &[u8] = b"qWp QHS-4.2 fors secret";
const FORS_LEAF_CONTEXT: &[u8] = b"qWp QHS-4.2 fors leaf";
const FORS_NODE_CONTEXT: &[u8] = b"qWp QHS-4.2 fors node";
const FORS_PK_CONTEXT: &[u8] = b"qWp QHS-4.2 fors-pk";
const CHECKSUM_CONTEXT: &[u8] = b"qWp QHS-4.2 signature-checksum";

/// Reusable BLAKE3 derive-key contexts for QHS-4.2 tree and signature work.
///
/// Creating this value once avoids repeating the BLAKE3 context hash for every
/// WOTS chain and secret derivation. It contains no secret material.
#[derive(Debug, Clone, Copy)]
pub struct Qhs42Contexts {
    chain: DeriveKey,
    wots_secret: DeriveKey,
    wots_pk: DeriveKey,
    leaf: DeriveKey,
    node: DeriveKey,
    fors_secret: DeriveKey,
    fors_leaf: DeriveKey,
    fors_node: DeriveKey,
    fors_pk: DeriveKey,
    wots_message: DeriveKey,
    checksum: DeriveKey,
}

impl Default for Qhs42Contexts {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Qhs42Contexts {
    /// Creates the QHS-4.2 context set.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            chain: DeriveKey::new(CHAIN_CONTEXT),
            wots_secret: DeriveKey::new(WOTS_SECRET_CONTEXT),
            wots_pk: DeriveKey::new(WOTS_PK_CONTEXT),
            leaf: DeriveKey::new(LEAF_CONTEXT),
            node: DeriveKey::new(NODE_CONTEXT),
            fors_secret: DeriveKey::new(FORS_SECRET_CONTEXT),
            fors_leaf: DeriveKey::new(FORS_LEAF_CONTEXT),
            fors_node: DeriveKey::new(FORS_NODE_CONTEXT),
            fors_pk: DeriveKey::new(FORS_PK_CONTEXT),
            wots_message: DeriveKey::new(WOTS_MESSAGE_CONTEXT),
            checksum: DeriveKey::new(CHECKSUM_CONTEXT),
        }
    }
}

/// A precomputed QHS-4.2 hypertree layer: root and authentication path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs42Tree {
    root: [u8; 32],
    auth_path: [[u8; 32]; TREE_HEIGHT],
}

impl Qhs42Tree {
    /// Creates a tree from its root and authentication path.
    #[must_use]
    #[inline]
    pub const fn new(root: [u8; 32], auth_path: [[u8; 32]; TREE_HEIGHT]) -> Self {
        Self { root, auth_path }
    }

    /// Returns the tree root.
    #[must_use]
    #[inline]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Returns the authentication path.
    #[must_use]
    #[inline]
    pub const fn auth_path(&self) -> &[[u8; 32]; TREE_HEIGHT] {
        &self.auth_path
    }
}

/// A precomputed QHS-4.2 FORS tree: root and authentication path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs42ForsTree {
    root: [u8; 32],
    auth_path: [[u8; 32]; FORS_HEIGHT],
}

impl Qhs42ForsTree {
    /// Creates a FORS tree from its root and authentication path.
    #[must_use]
    #[inline]
    pub const fn new(root: [u8; 32], auth_path: [[u8; 32]; FORS_HEIGHT]) -> Self {
        Self { root, auth_path }
    }

    /// Returns the tree root.
    #[must_use]
    #[inline]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Returns the authentication path.
    #[must_use]
    #[inline]
    pub const fn auth_path(&self) -> &[[u8; 32]; FORS_HEIGHT] {
        &self.auth_path
    }
}

/// A message-specific QHS-4.2 signing plan.
///
/// The plan records the randomizer, FORS digest, 64-bit path, and the layer
/// tree/leaf positions. It is public so a host parallel signer can compute the
/// tree leaves without re-deriving the plan for every worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs42SigningPlan {
    randomizer: [u8; 32],
    fors_digest: [u8; 32],
    tree_index: u64,
    bottom_tree: u64,
    bottom_leaf: u8,
    tree_indices: [u64; LAYERS],
    leaf_indices: [u8; LAYERS],
}

impl Qhs42SigningPlan {
    fn new(sk_seed: &[u8; 32], pk_seed: &[u8; 32], message: &[u8]) -> Self {
        let randomizer = derive_randomizer(sk_seed, message);
        let fors_digest = derive_fors_digest(&randomizer, pk_seed, message);
        let tree_index = derive_tree_index(&randomizer, pk_seed, message);
        let bottom_leaf = u8::try_from(tree_index & 0xff).unwrap_or(0);
        let bottom_tree = tree_index.checked_shr(8).unwrap_or(0);
        let mut tree_indices = [0_u64; LAYERS];
        let mut leaf_indices = [0_u8; LAYERS];
        for layer in 0..LAYERS {
            let shift = layer_shift(layer);
            let leaf_index =
                u8::try_from(tree_index.checked_shr(shift).unwrap_or(0) & 0xff).unwrap_or(0);
            let tree_index_l = if layer == LAYERS - 1 {
                0
            } else {
                tree_index
                    .checked_shr(shift.checked_add(8).unwrap_or(0))
                    .unwrap_or(0)
            };
            if let Some(slot) = tree_indices.get_mut(layer) {
                *slot = tree_index_l;
            }
            if let Some(slot) = leaf_indices.get_mut(layer) {
                *slot = leaf_index;
            }
        }
        Self {
            randomizer,
            fors_digest,
            tree_index,
            bottom_tree,
            bottom_leaf,
            tree_indices,
            leaf_indices,
        }
    }

    /// Returns the randomizer.
    #[must_use]
    #[inline]
    pub const fn randomizer(&self) -> [u8; 32] {
        self.randomizer
    }

    /// Returns the FORS digest.
    #[must_use]
    #[inline]
    pub const fn fors_digest(&self) -> [u8; 32] {
        self.fors_digest
    }

    /// Returns the 64-bit hypertree path.
    #[must_use]
    #[inline]
    pub const fn tree_index(&self) -> u64 {
        self.tree_index
    }

    /// Returns the bottom tree index.
    #[must_use]
    #[inline]
    pub const fn bottom_tree(&self) -> u64 {
        self.bottom_tree
    }

    /// Returns the bottom leaf index.
    #[must_use]
    #[inline]
    pub const fn bottom_leaf(&self) -> u8 {
        self.bottom_leaf
    }

    /// Returns the per-layer tree indices.
    #[must_use]
    #[inline]
    pub const fn tree_indices(&self) -> &[u64; LAYERS] {
        &self.tree_indices
    }

    /// Returns the per-layer leaf indices.
    #[must_use]
    #[inline]
    pub const fn leaf_indices(&self) -> &[u8; LAYERS] {
        &self.leaf_indices
    }
}

/// Derives a QHS-4.2 signing plan from a private key and message.
#[must_use]
#[inline]
pub fn qhs42_signing_plan(private_key: &Qhs42PrivateKey, message: &[u8]) -> Qhs42SigningPlan {
    Qhs42SigningPlan::new(private_key.sk_seed(), private_key.pk_seed(), message)
}

/// Computes a QHS-4.2 WOTS public key for one hypertree leaf.
#[must_use]
#[inline]
pub fn qhs42_wots_public_key(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    wots_pk_hash(sk_seed, pk_seed, layer, tree_index, leaf_index, contexts)
}

/// Computes a QHS-4.2 hypertree leaf.
#[must_use]
#[inline]
pub fn qhs42_leaf(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    let wots_pk = wots_pk_hash(sk_seed, pk_seed, layer, tree_index, leaf_index, contexts);
    leaf_hash(layer, tree_index, leaf_index, &wots_pk, contexts)
}

/// Computes a QHS-4.2 FORS leaf.
#[must_use]
#[inline]
pub fn qhs42_fors_leaf(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    tree_index: u64,
    leaf_index: u8,
    fors_tree: u8,
    fors_leaf: u8,
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    let secret = fors_secret(
        sk_seed, pk_seed, tree_index, leaf_index, fors_tree, fors_leaf, contexts,
    );
    fors_leaf_hash(fors_tree, fors_leaf, &secret, contexts)
}

/// Builds a QHS-4.2 hypertree root and auth path from precomputed leaves.
///
/// # Errors
///
/// Returns an internal error if the fixed-size layout is malformed.
#[inline]
pub fn qhs42_tree_root_and_auth_from_leaves(
    leaves: &[[u8; 32]; LEAF_COUNT],
    leaf_index: u8,
    contexts: &Qhs42Contexts,
) -> Result<([u8; 32], [[u8; 32]; TREE_HEIGHT]), CryptoError> {
    tree_from_leaves(leaves, leaf_index, contexts)
}

/// Builds a QHS-4.2 FORS root and auth path from precomputed leaves.
///
/// # Errors
///
/// Returns an internal error if the fixed-size layout is malformed.
#[inline]
pub fn qhs42_fors_root_and_auth_from_leaves(
    leaves: &[[u8; 32]; FORS_LEAVES],
    selected: u8,
    contexts: &Qhs42Contexts,
) -> Result<([u8; 32], [[u8; 32]; FORS_HEIGHT]), CryptoError> {
    fors_tree_from_leaves(leaves, selected, contexts)
}

/// A QHS-4.2 public key: `PK.seed` and a hypertree root.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs42PublicKey {
    bytes: [u8; QHS42_PUBLIC_KEY_BYTES],
}

impl Qhs42PublicKey {
    /// Creates a public key from `PK.seed` and a hypertree root.
    #[must_use]
    #[inline]
    pub fn from_root(pk_seed: [u8; 32], root: [u8; 32]) -> Self {
        let mut bytes = [0_u8; QHS42_PUBLIC_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..HEADER_BYTES) {
            slot.copy_from_slice(&KEY_HEADER);
        }
        if let Some(slot) = bytes.get_mut(4..36) {
            slot.copy_from_slice(&pk_seed);
        }
        if let Some(slot) = bytes.get_mut(36..68) {
            slot.copy_from_slice(&root);
        }
        Self { bytes }
    }

    /// Parses a public key from its exact 68-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, algorithm, height, or
    /// non-zero reserved bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS42_PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        let header = bytes
            .get(0..HEADER_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        if header != KEY_HEADER.as_slice() {
            return Err(CryptoError::InvalidLength);
        }
        let mut output = [0_u8; QHS42_PUBLIC_KEY_BYTES];
        output.copy_from_slice(bytes);
        Ok(Self { bytes: output })
    }

    /// Returns the exact 68-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS42_PUBLIC_KEY_BYTES] {
        self.bytes
    }

    /// Returns `PK.seed`.
    #[must_use]
    #[inline]
    pub fn seed(&self) -> [u8; 32] {
        let mut seed = [0_u8; 32];
        if let Some(slot) = self.bytes.get(4..36) {
            seed.copy_from_slice(slot);
        }
        seed
    }

    /// Returns the hypertree root.
    #[must_use]
    #[inline]
    pub fn root(&self) -> [u8; 32] {
        let mut root = [0_u8; 32];
        if let Some(slot) = self.bytes.get(36..68) {
            root.copy_from_slice(slot);
        }
        root
    }

    /// Verifies a QHS-4.2 signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerificationFailed`] for an invalid signature.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &Qhs42Signature) -> Result<(), CryptoError> {
        let bytes = signature.as_bytes();
        let header = bytes
            .get(0..HEADER_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        if header != KEY_HEADER.as_slice() {
            return Err(CryptoError::VerificationFailed);
        }
        let contexts = Qhs42Contexts::new();
        let body = bytes
            .get(..CHECKSUM_BODY_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let expected_checksum = signature_checksum(body, &contexts)?;
        let actual_checksum = bytes
            .get(CHECKSUM_OFFSET..QHS42_SIGNATURE_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        if actual_checksum != expected_checksum {
            return Err(CryptoError::VerificationFailed);
        }

        let randomizer = bytes
            .get(RANDOMIZER_OFFSET..FORS_OFFSET)
            .and_then(|slice| <[u8; RANDOMIZER_BYTES]>::try_from(slice).ok())
            .ok_or(CryptoError::VerificationFailed)?;
        let pk_seed = self.seed();
        let fors_digest = derive_fors_digest(&randomizer, &pk_seed, message);
        let tree_index = derive_tree_index(&randomizer, &pk_seed, message);
        let fors_pk = fors_verify(
            &fors_digest,
            bytes
                .get(FORS_OFFSET..LAYER_OFFSET)
                .ok_or(CryptoError::VerificationFailed)?,
            &contexts,
        )?;

        let mut previous_root = fors_pk;
        for layer in 0..LAYERS {
            let shift = layer_shift(layer);
            let leaf_index =
                u8::try_from(tree_index.checked_shr(shift).unwrap_or(0) & 0xff).unwrap_or(0);
            let tree_index_l = if layer == LAYERS - 1 {
                0
            } else {
                tree_index
                    .checked_shr(shift.checked_add(8).unwrap_or(0))
                    .unwrap_or(0)
            };
            let offset = LAYER_OFFSET
                .checked_add(layer.checked_mul(LAYER_BYTES).unwrap_or(0))
                .ok_or(CryptoError::VerificationFailed)?;
            let wots_end = offset
                .checked_add(WOTS_SIGNATURE_BYTES)
                .ok_or(CryptoError::VerificationFailed)?;
            let layer_end = offset
                .checked_add(LAYER_BYTES)
                .ok_or(CryptoError::VerificationFailed)?;
            let wots_signature = bytes
                .get(offset..wots_end)
                .ok_or(CryptoError::VerificationFailed)?;
            let auth_path = bytes
                .get(wots_end..layer_end)
                .ok_or(CryptoError::VerificationFailed)?;
            let wots_pk = wots_verify(wots_signature, &previous_root, &contexts)?;
            let leaf = leaf_hash(
                u8::try_from(layer).unwrap_or(0),
                tree_index_l,
                leaf_index,
                &wots_pk,
                &contexts,
            );
            previous_root = climb_path(leaf, auth_path, leaf_index, false, &contexts)?;
        }

        if previous_root == self.root() {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// A QHS-4.2 private key.
///
/// The key is stateless: signing never changes it. It is not `Clone`, is not
/// printable, and is wiped best-effort on drop.
pub struct Qhs42PrivateKey {
    header: [u8; HEADER_BYTES],
    sk_seed: [u8; 32],
    pk_seed: [u8; 32],
}

impl Qhs42PrivateKey {
    /// Creates a private key from its two seeds.
    ///
    /// The seeds must be generated by [`keygen`] or loaded from a validated
    /// key file. Reusing one `SK.seed` with different `PK.seed` values is
    /// forbidden.
    #[must_use]
    #[inline]
    pub const fn from_parts(sk_seed: [u8; 32], pk_seed: [u8; 32]) -> Self {
        Self {
            header: KEY_HEADER,
            sk_seed,
            pk_seed,
        }
    }

    /// Parses a private key from its exact 68-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, algorithm, height, or
    /// non-zero reserved bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8; QHS42_PRIVATE_KEY_BYTES]) -> Result<Self, CryptoError> {
        let header = bytes
            .get(0..HEADER_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        if header != KEY_HEADER.as_slice() {
            return Err(CryptoError::InvalidLength);
        }
        let sk_slice = bytes.get(4..36).ok_or(CryptoError::InvalidLength)?;
        let pk_slice = bytes.get(36..68).ok_or(CryptoError::InvalidLength)?;
        let mut sk_seed = [0_u8; 32];
        let mut pk_seed = [0_u8; 32];
        sk_seed.copy_from_slice(sk_slice);
        pk_seed.copy_from_slice(pk_slice);
        Ok(Self {
            header: KEY_HEADER,
            sk_seed,
            pk_seed,
        })
    }

    /// Returns the exact 68-byte representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; QHS42_PRIVATE_KEY_BYTES] {
        let mut bytes = [0_u8; QHS42_PRIVATE_KEY_BYTES];
        if let Some(slot) = bytes.get_mut(0..HEADER_BYTES) {
            slot.copy_from_slice(&self.header);
        }
        if let Some(slot) = bytes.get_mut(4..36) {
            slot.copy_from_slice(&self.sk_seed);
        }
        if let Some(slot) = bytes.get_mut(36..68) {
            slot.copy_from_slice(&self.pk_seed);
        }
        bytes
    }

    /// Returns `SK.seed`.
    #[must_use]
    #[inline]
    pub const fn sk_seed(&self) -> &[u8; 32] {
        &self.sk_seed
    }

    /// Returns `PK.seed`.
    #[must_use]
    #[inline]
    pub const fn pk_seed(&self) -> &[u8; 32] {
        &self.pk_seed
    }

    /// Signs a message statelessly.
    ///
    /// # Errors
    ///
    /// Returns an internal error if a fixed-size layout is malformed.
    #[inline]
    #[allow(
        clippy::large_stack_arrays,
        reason = "the fixed QHS-4.2 signature is 14,344 bytes and this crate is no_std"
    )]
    pub fn sign(&self, message: &[u8]) -> Result<Qhs42Signature, CryptoError> {
        let randomizer = derive_randomizer(&self.sk_seed, message);
        let fors_digest = derive_fors_digest(&randomizer, &self.pk_seed, message);
        let tree_index = derive_tree_index(&randomizer, &self.pk_seed, message);
        let bottom_leaf = u8::try_from(tree_index & 0xff).unwrap_or(0);
        let bottom_tree = tree_index.checked_shr(8).unwrap_or(0);
        let contexts = Qhs42Contexts::new();

        let fors_pk = fors_public_key(
            &self.sk_seed,
            &self.pk_seed,
            bottom_tree,
            bottom_leaf,
            &contexts,
        )?;
        let mut signature = Qhs42Signature {
            bytes: [0_u8; QHS42_SIGNATURE_BYTES],
        };
        write_header(&mut signature, &randomizer)?;
        write_fors_signature(
            &mut signature,
            &self.sk_seed,
            &self.pk_seed,
            bottom_tree,
            bottom_leaf,
            &fors_digest,
            &contexts,
        )?;
        write_hypertree(
            &mut signature,
            &self.sk_seed,
            &self.pk_seed,
            tree_index,
            fors_pk,
            &contexts,
        )?;
        write_checksum(&mut signature, &contexts)?;
        Ok(signature)
    }
}

fn write_header(signature: &mut Qhs42Signature, randomizer: &[u8; 32]) -> Result<(), CryptoError> {
    let header = signature
        .bytes
        .get_mut(0..HEADER_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    header.copy_from_slice(&KEY_HEADER);
    let slot = signature
        .bytes
        .get_mut(RANDOMIZER_OFFSET..FORS_OFFSET)
        .ok_or(CryptoError::InvalidLength)?;
    slot.copy_from_slice(randomizer);
    Ok(())
}

fn write_fors_signature(
    signature: &mut Qhs42Signature,
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    bottom_tree: u64,
    bottom_leaf: u8,
    fors_digest: &[u8; 32],
    contexts: &Qhs42Contexts,
) -> Result<(), CryptoError> {
    for fors_tree in 0..FORS_TREES {
        let tree_u8 = u8::try_from(fors_tree).unwrap_or(0);
        let selected = *fors_digest
            .get(fors_tree)
            .ok_or(CryptoError::InvalidLength)?;
        let secret = fors_secret(
            sk_seed,
            pk_seed,
            bottom_tree,
            bottom_leaf,
            tree_u8,
            selected,
            contexts,
        );
        let (_, auth_path) = fors_root_and_auth(
            sk_seed,
            pk_seed,
            bottom_tree,
            bottom_leaf,
            tree_u8,
            selected,
            contexts,
        )?;
        let offset = FORS_OFFSET
            .checked_add(fors_tree.checked_mul(FORS_ENTRY_BYTES).unwrap_or(0))
            .ok_or(CryptoError::InvalidLength)?;
        let secret_end = offset
            .checked_add(FORS_SECRET_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        let entry_end = offset
            .checked_add(FORS_ENTRY_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        let secret_slot = signature
            .bytes
            .get_mut(offset..secret_end)
            .ok_or(CryptoError::InvalidLength)?;
        secret_slot.copy_from_slice(&secret);
        let auth_slot = signature
            .bytes
            .get_mut(secret_end..entry_end)
            .ok_or(CryptoError::InvalidLength)?;
        for (destination, source) in auth_slot
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip(auth_path.iter())
        {
            destination.copy_from_slice(source);
        }
    }
    Ok(())
}

fn write_hypertree(
    signature: &mut Qhs42Signature,
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    tree_index: u64,
    fors_pk: [u8; 32],
    contexts: &Qhs42Contexts,
) -> Result<(), CryptoError> {
    let mut previous_root = fors_pk;
    for layer in 0..LAYERS {
        let shift = layer_shift(layer);
        let leaf_index =
            u8::try_from(tree_index.checked_shr(shift).unwrap_or(0) & 0xff).unwrap_or(0);
        let tree_index_l = if layer == LAYERS - 1 {
            0
        } else {
            tree_index
                .checked_shr(shift.checked_add(8).unwrap_or(0))
                .unwrap_or(0)
        };
        let layer_u8 = u8::try_from(layer).unwrap_or(0);
        let wots_signature = wots_sign(
            sk_seed,
            pk_seed,
            layer_u8,
            tree_index_l,
            leaf_index,
            &previous_root,
            contexts,
        )?;
        let (root, auth_path) = tree_root_and_auth(
            sk_seed,
            pk_seed,
            layer_u8,
            tree_index_l,
            leaf_index,
            contexts,
        )?;
        let offset = LAYER_OFFSET
            .checked_add(layer.checked_mul(LAYER_BYTES).unwrap_or(0))
            .ok_or(CryptoError::InvalidLength)?;
        let wots_end = offset
            .checked_add(WOTS_SIGNATURE_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        let layer_end = offset
            .checked_add(LAYER_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        let wots_slot = signature
            .bytes
            .get_mut(offset..wots_end)
            .ok_or(CryptoError::InvalidLength)?;
        wots_slot.copy_from_slice(&wots_signature);
        let auth_slot = signature
            .bytes
            .get_mut(wots_end..layer_end)
            .ok_or(CryptoError::InvalidLength)?;
        for (destination, source) in auth_slot
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip(auth_path.iter())
        {
            destination.copy_from_slice(source);
        }
        previous_root = root;
    }
    Ok(())
}

fn write_checksum(
    signature: &mut Qhs42Signature,
    contexts: &Qhs42Contexts,
) -> Result<(), CryptoError> {
    let body = signature
        .bytes
        .get(..CHECKSUM_BODY_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    let checksum = signature_checksum(body, contexts)?;
    let slot = signature
        .bytes
        .get_mut(CHECKSUM_OFFSET..QHS42_SIGNATURE_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    slot.copy_from_slice(&checksum);
    Ok(())
}

fn auth_path_bytes(path: &[[u8; 32]]) -> Result<[u8; AUTH_PATH_BYTES], CryptoError> {
    if path.len() != TREE_HEIGHT {
        return Err(CryptoError::InternalFailure);
    }
    let mut bytes = [0_u8; AUTH_PATH_BYTES];
    for (destination, source) in bytes.as_chunks_mut::<32>().0.iter_mut().zip(path.iter()) {
        destination.copy_from_slice(source);
    }
    Ok(bytes)
}

fn fors_public_key_from_trees(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    plan: &Qhs42SigningPlan,
    fors: &[Qhs42ForsTree; FORS_TREES],
    contexts: &Qhs42Contexts,
) -> Result<[u8; 32], CryptoError> {
    let mut hasher = contexts.fors_pk.hasher();
    for (tree_index, tree) in fors.iter().enumerate() {
        let selected = *plan
            .fors_digest
            .get(tree_index)
            .ok_or(CryptoError::InternalFailure)?;
        let tree_u8 = u8::try_from(tree_index).map_err(|_| CryptoError::InternalFailure)?;
        let secret = fors_secret(
            sk_seed,
            pk_seed,
            plan.bottom_tree,
            plan.bottom_leaf,
            tree_u8,
            selected,
            contexts,
        );
        let leaf = fors_leaf_hash(tree_u8, selected, &secret, contexts);
        let auth = auth_path_bytes(tree.auth_path())?;
        let root = climb_path(leaf, &auth, selected, true, contexts)?;
        if root != tree.root() {
            return Err(CryptoError::InternalFailure);
        }
        hasher.update(&root);
    }
    Ok(hasher.finalize().to_bytes())
}

fn verify_hypertree_trees(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    plan: &Qhs42SigningPlan,
    hypertree: &[Qhs42Tree; LAYERS],
    contexts: &Qhs42Contexts,
) -> Result<(), CryptoError> {
    for (layer, tree) in hypertree.iter().enumerate() {
        let layer_u8 = u8::try_from(layer).map_err(|_| CryptoError::InternalFailure)?;
        let tree_index_l = *plan
            .tree_indices
            .get(layer)
            .ok_or(CryptoError::InternalFailure)?;
        let leaf_index = *plan
            .leaf_indices
            .get(layer)
            .ok_or(CryptoError::InternalFailure)?;
        let wots_pk = wots_pk_hash(
            sk_seed,
            pk_seed,
            layer_u8,
            tree_index_l,
            leaf_index,
            contexts,
        );
        let leaf = leaf_hash(layer_u8, tree_index_l, leaf_index, &wots_pk, contexts);
        let auth = auth_path_bytes(tree.auth_path())?;
        let root = climb_path(leaf, &auth, leaf_index, false, contexts)?;
        if root != tree.root() {
            return Err(CryptoError::InternalFailure);
        }
    }
    Ok(())
}

fn write_fors_from_trees(
    signature: &mut Qhs42Signature,
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    plan: &Qhs42SigningPlan,
    fors: &[Qhs42ForsTree; FORS_TREES],
    contexts: &Qhs42Contexts,
) -> Result<(), CryptoError> {
    for (tree_index, tree) in fors.iter().enumerate() {
        let selected = *plan
            .fors_digest
            .get(tree_index)
            .ok_or(CryptoError::InternalFailure)?;
        let tree_u8 = u8::try_from(tree_index).map_err(|_| CryptoError::InternalFailure)?;
        let secret = fors_secret(
            sk_seed,
            pk_seed,
            plan.bottom_tree,
            plan.bottom_leaf,
            tree_u8,
            selected,
            contexts,
        );
        let offset = FORS_OFFSET
            .checked_add(tree_index.checked_mul(FORS_ENTRY_BYTES).unwrap_or(0))
            .ok_or(CryptoError::InternalFailure)?;
        let secret_end = offset
            .checked_add(FORS_SECRET_BYTES)
            .ok_or(CryptoError::InternalFailure)?;
        let entry_end = offset
            .checked_add(FORS_ENTRY_BYTES)
            .ok_or(CryptoError::InternalFailure)?;
        let secret_slot = signature
            .bytes
            .get_mut(offset..secret_end)
            .ok_or(CryptoError::InternalFailure)?;
        secret_slot.copy_from_slice(&secret);
        let auth_slot = signature
            .bytes
            .get_mut(secret_end..entry_end)
            .ok_or(CryptoError::InternalFailure)?;
        for (destination, source) in auth_slot
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip(tree.auth_path().iter())
        {
            destination.copy_from_slice(source);
        }
    }
    Ok(())
}

fn write_hypertree_from_trees(
    signature: &mut Qhs42Signature,
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    plan: &Qhs42SigningPlan,
    hypertree: &[Qhs42Tree; LAYERS],
    fors_pk: [u8; 32],
    contexts: &Qhs42Contexts,
) -> Result<(), CryptoError> {
    let mut previous_root = fors_pk;
    for (layer, tree) in hypertree.iter().enumerate() {
        let layer_u8 = u8::try_from(layer).map_err(|_| CryptoError::InternalFailure)?;
        let tree_index_l = *plan
            .tree_indices
            .get(layer)
            .ok_or(CryptoError::InternalFailure)?;
        let leaf_index = *plan
            .leaf_indices
            .get(layer)
            .ok_or(CryptoError::InternalFailure)?;
        let wots_signature = wots_sign(
            sk_seed,
            pk_seed,
            layer_u8,
            tree_index_l,
            leaf_index,
            &previous_root,
            contexts,
        )?;
        let offset = LAYER_OFFSET
            .checked_add(layer.checked_mul(LAYER_BYTES).unwrap_or(0))
            .ok_or(CryptoError::InternalFailure)?;
        let wots_end = offset
            .checked_add(WOTS_SIGNATURE_BYTES)
            .ok_or(CryptoError::InternalFailure)?;
        let layer_end = offset
            .checked_add(LAYER_BYTES)
            .ok_or(CryptoError::InternalFailure)?;
        let wots_slot = signature
            .bytes
            .get_mut(offset..wots_end)
            .ok_or(CryptoError::InternalFailure)?;
        wots_slot.copy_from_slice(&wots_signature);
        let auth_slot = signature
            .bytes
            .get_mut(wots_end..layer_end)
            .ok_or(CryptoError::InternalFailure)?;
        for (destination, source) in auth_slot
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip(tree.auth_path().iter())
        {
            destination.copy_from_slice(source);
        }
        previous_root = tree.root();
    }
    Ok(())
}

/// Assembles a QHS-4.2 signature from precomputed hypertree and FORS trees.
///
/// The trees must be derived from the same private key and message. The
/// function re-derives the plan and checks the selected leaf paths before
/// writing the signature, so a mismatched tree is rejected.
///
/// # Errors
///
/// Returns an internal error if the plan or a tree does not match the key and
/// message.
#[inline]
#[allow(
    clippy::large_stack_arrays,
    reason = "the fixed QHS-4.2 signature is 14,344 bytes and this crate is no_std"
)]
pub fn qhs42_sign_with_trees(
    private_key: &Qhs42PrivateKey,
    message: &[u8],
    plan: &Qhs42SigningPlan,
    hypertree: &[Qhs42Tree; LAYERS],
    fors: &[Qhs42ForsTree; FORS_TREES],
) -> Result<Qhs42Signature, CryptoError> {
    let expected = Qhs42SigningPlan::new(private_key.sk_seed(), private_key.pk_seed(), message);
    if expected != *plan {
        return Err(CryptoError::InternalFailure);
    }
    let contexts = Qhs42Contexts::new();
    let sk_seed = private_key.sk_seed();
    let pk_seed = private_key.pk_seed();
    let fors_pk = fors_public_key_from_trees(sk_seed, pk_seed, plan, fors, &contexts)?;
    verify_hypertree_trees(sk_seed, pk_seed, plan, hypertree, &contexts)?;

    let mut signature = Qhs42Signature {
        bytes: [0_u8; QHS42_SIGNATURE_BYTES],
    };
    write_header(&mut signature, &plan.randomizer)?;
    write_fors_from_trees(&mut signature, sk_seed, pk_seed, plan, fors, &contexts)?;
    write_hypertree_from_trees(
        &mut signature,
        sk_seed,
        pk_seed,
        plan,
        hypertree,
        fors_pk,
        &contexts,
    )?;
    write_checksum(&mut signature, &contexts)?;
    Ok(signature)
}

impl Drop for Qhs42PrivateKey {
    #[inline]
    fn drop(&mut self) {
        self.header.fill(0);
        self.sk_seed.fill(0);
        self.pk_seed.fill(0);
    }
}

impl fmt::Debug for Qhs42PrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Qhs42PrivateKey")
            .finish_non_exhaustive()
    }
}

/// A QHS-4.2 signature.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs42Signature {
    bytes: [u8; QHS42_SIGNATURE_BYTES],
}

impl Qhs42Signature {
    /// Creates a signature from its exact 14,344-byte representation.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; QHS42_SIGNATURE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Parses a signature from a byte slice of exactly 14,344 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] for any other length.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; QHS42_SIGNATURE_BYTES] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self { bytes: array })
    }

    /// Returns the exact 14,344-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS42_SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; QHS42_SIGNATURE_BYTES] {
        &self.bytes
    }
}

/// Generates a QHS-4.2 key pair from a 32-byte seed.
///
/// # Errors
///
/// Returns an internal error if a fixed-size layout is malformed.
#[inline]
pub fn keygen(seed: &[u8; 32]) -> Result<(Qhs42PrivateKey, Qhs42PublicKey), CryptoError> {
    let sk_seed = derive_key32(SK_SEED_CONTEXT, seed).to_bytes();
    let pk_seed = derive_key32(PK_SEED_CONTEXT, seed).to_bytes();
    let contexts = Qhs42Contexts::new();
    let top_layer = u8::try_from(LAYERS.saturating_sub(1)).unwrap_or(0);
    let (root, _) = tree_root_and_auth(&sk_seed, &pk_seed, top_layer, 0, 0, &contexts)?;
    Ok((
        Qhs42PrivateKey::from_parts(sk_seed, pk_seed),
        Qhs42PublicKey::from_root(pk_seed, root),
    ))
}

fn layer_shift(layer: usize) -> u32 {
    u32::try_from(layer)
        .unwrap_or(0)
        .checked_mul(8)
        .unwrap_or(0)
}

fn derive_randomizer(sk_seed: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(RANDOMIZER_CONTEXT);
    hasher.update(sk_seed);
    hasher.update(message);
    hasher.finalize().to_bytes()
}

fn derive_fors_digest(randomizer: &[u8; 32], pk_seed: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(FORS_DIGEST_CONTEXT);
    hasher.update(randomizer);
    hasher.update(pk_seed);
    hasher.update(message);
    hasher.finalize().to_bytes()
}

fn derive_tree_index(randomizer: &[u8; 32], pk_seed: &[u8; 32], message: &[u8]) -> u64 {
    let mut hasher = Hasher::new_derive_key(TREE_INDEX_CONTEXT);
    hasher.update(randomizer);
    hasher.update(pk_seed);
    hasher.update(message);
    let digest = hasher.finalize().to_bytes();
    let mut word = [0_u8; 8];
    if let Some(slot) = digest.get(..8) {
        word.copy_from_slice(slot);
    }
    u64::from_le_bytes(word)
}

fn wots_secret(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    chain_index: u8,
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    let mut hasher = contexts.wots_secret.hasher();
    hasher.update(sk_seed);
    hasher.update(pk_seed);
    hasher.update(&[layer]);
    hasher.update(&tree_index.to_le_bytes());
    hasher.update(&[leaf_index, chain_index]);
    hasher.finalize().to_bytes()
}

fn chain_hash(value: &[u8; 32], contexts: &Qhs42Contexts) -> [u8; 32] {
    contexts.chain.hash32(value).to_bytes()
}

fn wots_pk_hash(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    let mut hasher = contexts.wots_pk.hasher();
    for chain_index in 0..WOTS_CHAINS {
        let chain_u8 = u8::try_from(chain_index).unwrap_or(0);
        let mut value = wots_secret(
            sk_seed, pk_seed, layer, tree_index, leaf_index, chain_u8, contexts,
        );
        for _ in 0..WOTS_CHAIN_LEN {
            value = chain_hash(&value, contexts);
        }
        hasher.update(&value);
    }
    hasher.finalize().to_bytes()
}

fn leaf_hash(
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    wots_pk: &[u8; 32],
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    let mut hasher = contexts.leaf.hasher();
    hasher.update(&[layer]);
    hasher.update(&tree_index.to_le_bytes());
    hasher.update(&[leaf_index]);
    hasher.update(wots_pk);
    hasher.finalize().to_bytes()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32], contexts: &Qhs42Contexts) -> [u8; 32] {
    let mut input = [0_u8; 64];
    if let Some(slot) = input.get_mut(0..32) {
        slot.copy_from_slice(left);
    }
    if let Some(slot) = input.get_mut(32..64) {
        slot.copy_from_slice(right);
    }
    contexts.node.hash32(&input).to_bytes()
}

fn tree_root_and_auth(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    contexts: &Qhs42Contexts,
) -> Result<([u8; 32], [[u8; 32]; TREE_HEIGHT]), CryptoError> {
    let mut leaves = [[0_u8; 32]; LEAF_COUNT];
    for (index, slot) in leaves.iter_mut().enumerate() {
        let leaf = u8::try_from(index).map_err(|_| CryptoError::InvalidLength)?;
        let wots_pk = wots_pk_hash(sk_seed, pk_seed, layer, tree_index, leaf, contexts);
        *slot = leaf_hash(layer, tree_index, leaf, &wots_pk, contexts);
    }
    tree_from_leaves(&leaves, leaf_index, contexts)
}

fn tree_from_leaves(
    leaves: &[[u8; 32]; LEAF_COUNT],
    leaf_index: u8,
    contexts: &Qhs42Contexts,
) -> Result<([u8; 32], [[u8; 32]; TREE_HEIGHT]), CryptoError> {
    let mut nodes = *leaves;
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
            let parent = node_hash(&left, &right, contexts);
            if let Some(slot) = nodes.get_mut(index) {
                *slot = parent;
            }
        }
        count = half;
    }

    let root = nodes.first().copied().ok_or(CryptoError::InvalidLength)?;
    Ok((root, path))
}

fn climb_path(
    mut node: [u8; 32],
    auth_path: &[u8],
    leaf_index: u8,
    fors: bool,
    contexts: &Qhs42Contexts,
) -> Result<[u8; 32], CryptoError> {
    if auth_path.len() != AUTH_PATH_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    for (level, sibling) in auth_path.as_chunks::<32>().0.iter().enumerate() {
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let bit = usize::from(leaf_index).checked_shr(level_u32).unwrap_or(0) & 1;
        node = if bit == 0 {
            if fors {
                fors_node_hash(&node, sibling, contexts)
            } else {
                node_hash(&node, sibling, contexts)
            }
        } else if fors {
            fors_node_hash(sibling, &node, contexts)
        } else {
            node_hash(sibling, &node, contexts)
        };
    }
    Ok(node)
}

fn fors_secret(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    tree_index: u64,
    leaf_index: u8,
    fors_tree: u8,
    fors_leaf: u8,
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    let mut hasher = contexts.fors_secret.hasher();
    hasher.update(sk_seed);
    hasher.update(pk_seed);
    hasher.update(&tree_index.to_le_bytes());
    hasher.update(&[leaf_index, fors_tree, fors_leaf]);
    hasher.finalize().to_bytes()
}

fn fors_leaf_hash(
    fors_tree: u8,
    fors_leaf: u8,
    secret: &[u8; 32],
    contexts: &Qhs42Contexts,
) -> [u8; 32] {
    let mut hasher = contexts.fors_leaf.hasher();
    hasher.update(&[fors_tree, fors_leaf]);
    hasher.update(secret);
    hasher.finalize().to_bytes()
}

fn fors_node_hash(left: &[u8; 32], right: &[u8; 32], contexts: &Qhs42Contexts) -> [u8; 32] {
    let mut input = [0_u8; 64];
    if let Some(slot) = input.get_mut(0..32) {
        slot.copy_from_slice(left);
    }
    if let Some(slot) = input.get_mut(32..64) {
        slot.copy_from_slice(right);
    }
    contexts.fors_node.hash32(&input).to_bytes()
}

fn fors_root_and_auth(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    tree_index: u64,
    leaf_index: u8,
    fors_tree: u8,
    selected: u8,
    contexts: &Qhs42Contexts,
) -> Result<([u8; 32], [[u8; 32]; FORS_HEIGHT]), CryptoError> {
    let mut leaves = [[0_u8; 32]; FORS_LEAVES];
    for (index, slot) in leaves.iter_mut().enumerate() {
        let leaf = u8::try_from(index).map_err(|_| CryptoError::InvalidLength)?;
        let secret = fors_secret(
            sk_seed, pk_seed, tree_index, leaf_index, fors_tree, leaf, contexts,
        );
        *slot = fors_leaf_hash(fors_tree, leaf, &secret, contexts);
    }
    fors_tree_from_leaves(&leaves, selected, contexts)
}

fn fors_tree_from_leaves(
    leaves: &[[u8; 32]; FORS_LEAVES],
    selected: u8,
    contexts: &Qhs42Contexts,
) -> Result<([u8; 32], [[u8; 32]; FORS_HEIGHT]), CryptoError> {
    let mut nodes = *leaves;
    let mut path = [[0_u8; 32]; FORS_HEIGHT];
    let mut count = FORS_LEAVES;
    for level in 0..FORS_HEIGHT {
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let sibling_index = usize::from(selected).checked_shr(level_u32).unwrap_or(0) ^ 1;
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
            let parent = fors_node_hash(&left, &right, contexts);
            if let Some(slot) = nodes.get_mut(index) {
                *slot = parent;
            }
        }
        count = half;
    }

    let root = nodes.first().copied().ok_or(CryptoError::InvalidLength)?;
    Ok((root, path))
}

fn fors_public_key(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    tree_index: u64,
    leaf_index: u8,
    contexts: &Qhs42Contexts,
) -> Result<[u8; 32], CryptoError> {
    let mut hasher = contexts.fors_pk.hasher();
    for fors_tree in 0..FORS_TREES {
        let tree_u8 = u8::try_from(fors_tree).unwrap_or(0);
        let (root, _) = fors_root_and_auth(
            sk_seed, pk_seed, tree_index, leaf_index, tree_u8, 0, contexts,
        )?;
        hasher.update(&root);
    }
    Ok(hasher.finalize().to_bytes())
}

fn fors_verify(
    digest: &[u8; 32],
    signature: &[u8],
    contexts: &Qhs42Contexts,
) -> Result<[u8; 32], CryptoError> {
    if signature.len() != FORS_SIGNATURE_BYTES {
        return Err(CryptoError::VerificationFailed);
    }
    let mut hasher = contexts.fors_pk.hasher();
    for fors_tree in 0..FORS_TREES {
        let selected = *digest
            .get(fors_tree)
            .ok_or(CryptoError::VerificationFailed)?;
        let offset = fors_tree
            .checked_mul(FORS_ENTRY_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let secret_end = offset
            .checked_add(FORS_SECRET_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let entry_end = offset
            .checked_add(FORS_ENTRY_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let secret = signature
            .get(offset..secret_end)
            .and_then(|slice| <[u8; 32]>::try_from(slice).ok())
            .ok_or(CryptoError::VerificationFailed)?;
        let auth_path = signature
            .get(secret_end..entry_end)
            .ok_or(CryptoError::VerificationFailed)?;
        let leaf = fors_leaf_hash(
            u8::try_from(fors_tree).unwrap_or(0),
            selected,
            &secret,
            contexts,
        );
        let root = climb_path(leaf, auth_path, selected, true, contexts)?;
        hasher.update(&root);
    }
    Ok(hasher.finalize().to_bytes())
}

fn message_digits(message: &[u8; 32], contexts: &Qhs42Contexts) -> [u8; WOTS_CHAINS] {
    let digest = contexts.wots_message.hash32(message).to_bytes();
    let mut digits = [0_u8; WOTS_CHAINS];

    // 32 base-256 message digits are the 32 digest bytes.
    for (index, byte) in digest.iter().enumerate() {
        if let Some(slot) = digits.get_mut(index) {
            *slot = *byte;
        }
    }

    // Two base-256 checksum digits encode the value in 0..=8160.
    let mut checksum = 0_u16;
    for digit in digits.iter().take(MESSAGE_DIGITS) {
        checksum = checksum.wrapping_add(255_u16.saturating_sub(u16::from(*digit)));
    }
    if let Some(slot) = digits.get_mut(MESSAGE_DIGITS) {
        *slot = u8::try_from(checksum.wrapping_shr(8)).unwrap_or(0);
    }
    if let Some(slot) = digits.get_mut(MESSAGE_DIGITS.checked_add(1).unwrap_or(0)) {
        *slot = u8::try_from(checksum & 0xff).unwrap_or(0);
    }
    digits
}

fn wots_sign(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    message: &[u8; 32],
    contexts: &Qhs42Contexts,
) -> Result<[u8; WOTS_SIGNATURE_BYTES], CryptoError> {
    let digits = message_digits(message, contexts);
    let mut signature = [0_u8; WOTS_SIGNATURE_BYTES];
    for (chain_index, (slot, digit)) in signature
        .as_chunks_mut::<32>()
        .0
        .iter_mut()
        .zip(digits.iter())
        .enumerate()
    {
        let chain_u8 = u8::try_from(chain_index).map_err(|_| CryptoError::InvalidLength)?;
        let mut value = wots_secret(
            sk_seed, pk_seed, layer, tree_index, leaf_index, chain_u8, contexts,
        );
        for _ in 0..*digit {
            value = chain_hash(&value, contexts);
        }
        slot.copy_from_slice(&value);
    }
    Ok(signature)
}

fn wots_verify(
    signature: &[u8],
    message: &[u8; 32],
    contexts: &Qhs42Contexts,
) -> Result<[u8; 32], CryptoError> {
    if signature.len() != WOTS_SIGNATURE_BYTES {
        return Err(CryptoError::VerificationFailed);
    }
    let digits = message_digits(message, contexts);
    let mut hasher = contexts.wots_pk.hasher();
    for (slot, digit) in signature.as_chunks::<32>().0.iter().zip(digits.iter()) {
        let mut value = [0_u8; 32];
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
    contexts: &Qhs42Contexts,
) -> Result<[u8; CHECKSUM_BYTES], CryptoError> {
    let hash = contexts.checksum.hash32(body);
    let mut checksum = [0_u8; CHECKSUM_BYTES];
    let source = hash
        .as_bytes()
        .get(..CHECKSUM_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    checksum.copy_from_slice(source);
    Ok(checksum)
}

const _: [(); QHS42_PUBLIC_KEY_BYTES] = [(); size_of::<Qhs42PublicKey>()];
const _: [(); QHS42_PRIVATE_KEY_BYTES] = [(); size_of::<Qhs42PrivateKey>()];
const _: [(); QHS42_SIGNATURE_BYTES] = [(); size_of::<Qhs42Signature>()];
const _: [(); 14_344] = [(); QHS42_SIGNATURE_BYTES];
const _: [(); 56] = [(); TOTAL_HEIGHT];

#[cfg(test)]
mod tests {
    #![allow(
        clippy::large_stack_arrays,
        clippy::std_instead_of_alloc,
        reason = "tests use the fixed QHS-4.2 signature size and std for formatting"
    )]

    use super::{
        CHAIN_CONTEXT, CHECKSUM_CONTEXT, FORS_DIGEST_CONTEXT, FORS_LEAF_CONTEXT, FORS_LEAVES,
        FORS_NODE_CONTEXT, FORS_PK_CONTEXT, FORS_SECRET_CONTEXT, LAYERS, LEAF_CONTEXT, LEAF_COUNT,
        MESSAGE_DIGITS, NODE_CONTEXT, PK_SEED_CONTEXT, QHS42_FORS_BYTES, QHS42_SIGNATURE_BYTES,
        Qhs42PrivateKey, Qhs42PublicKey, Qhs42Signature, RANDOMIZER_CONTEXT, SK_SEED_CONTEXT,
        TREE_INDEX_CONTEXT, WOTS_CHAINS, WOTS_MESSAGE_CONTEXT, WOTS_PK_CONTEXT,
        WOTS_SECRET_CONTEXT,
    };
    use core::mem::size_of;
    use qwp_core::CryptoError;

    #[test]
    fn signature_size_is_exact() {
        assert_eq!(size_of::<Qhs42Signature>(), QHS42_SIGNATURE_BYTES);
        assert_eq!(QHS42_SIGNATURE_BYTES, 14_344);
        assert_eq!(QHS42_FORS_BYTES, 4_896);
    }

    #[test]
    fn public_key_round_trip() {
        let public_key = Qhs42PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let bytes = public_key.to_bytes();
        assert_eq!(Qhs42PublicKey::from_bytes(&bytes), Ok(public_key));
        assert_eq!(public_key.seed(), [1_u8; 32]);
        assert_eq!(public_key.root(), [2_u8; 32]);
    }

    #[test]
    fn public_key_rejects_bad_header() {
        let public_key = Qhs42PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let original = public_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs42PublicKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn private_key_round_trip() {
        let private_key = Qhs42PrivateKey::from_parts([1_u8; 32], [2_u8; 32]);
        let bytes = private_key.to_bytes();
        assert_eq!(&bytes[..4], &[5, 5, 56, 0]);
        assert_eq!(&bytes[4..36], &[1_u8; 32]);
        assert_eq!(&bytes[36..68], &[2_u8; 32]);
        let parsed = Qhs42PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sk_seed(), &[1_u8; 32]);
        assert_eq!(parsed.pk_seed(), &[2_u8; 32]);
    }

    #[test]
    fn private_key_rejects_bad_header() {
        let private_key = Qhs42PrivateKey::from_parts([1_u8; 32], [2_u8; 32]);
        let original = private_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs42PrivateKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let private_key = Qhs42PrivateKey::from_parts([1_u8; 32], [2_u8; 32]);
        let debug = std::format!("{private_key:?}");
        assert!(debug.contains("Qhs42PrivateKey"));
        assert!(!debug.contains("seed"));
    }

    #[test]
    fn signature_round_trip_and_slice() {
        let signature = Qhs42Signature::from_bytes([3_u8; QHS42_SIGNATURE_BYTES]);
        let bytes = signature.to_bytes();
        assert_eq!(Qhs42Signature::from_slice(&bytes), Ok(signature));
        assert!(Qhs42Signature::from_slice(&bytes[..QHS42_SIGNATURE_BYTES - 1]).is_err());
    }

    #[test]
    fn verify_rejects_zero_signature() {
        let public_key = Qhs42PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let signature = Qhs42Signature::from_bytes([0_u8; QHS42_SIGNATURE_BYTES]);
        assert_eq!(
            public_key.verify(b"message", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn verify_rejects_bad_header_with_valid_checksum() {
        let public_key = Qhs42PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let mut bytes = [0_u8; QHS42_SIGNATURE_BYTES];
        if let Some(header) = bytes.get_mut(0..4) {
            header.copy_from_slice(&[4, 5, 56, 0]);
        }
        let body = bytes.get(..super::CHECKSUM_BODY_BYTES).unwrap();
        let checksum = super::signature_checksum(body, &super::Qhs42Contexts::new()).unwrap();
        if let Some(slot) = bytes.get_mut(super::CHECKSUM_OFFSET..) {
            slot.copy_from_slice(&checksum);
        }
        let signature = Qhs42Signature::from_bytes(bytes);
        assert_eq!(
            public_key.verify(b"message", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn domain_contexts_are_distinct() {
        let contexts = [
            SK_SEED_CONTEXT,
            PK_SEED_CONTEXT,
            RANDOMIZER_CONTEXT,
            FORS_DIGEST_CONTEXT,
            TREE_INDEX_CONTEXT,
            WOTS_SECRET_CONTEXT,
            CHAIN_CONTEXT,
            WOTS_MESSAGE_CONTEXT,
            WOTS_PK_CONTEXT,
            LEAF_CONTEXT,
            NODE_CONTEXT,
            FORS_SECRET_CONTEXT,
            FORS_LEAF_CONTEXT,
            FORS_NODE_CONTEXT,
            FORS_PK_CONTEXT,
            CHECKSUM_CONTEXT,
        ];
        for (index, left) in contexts.iter().enumerate() {
            for right in contexts.iter().skip(index.saturating_add(1)) {
                assert_ne!(left, right);
            }
        }
    }

    #[test]
    fn message_digits_shape_and_checksum() {
        let message = [0x42_u8; 32];
        let contexts = super::Qhs42Contexts::new();
        let digest = contexts.wots_message.hash32(&message).to_bytes();
        let digits = super::message_digits(&message, &contexts);
        assert_eq!(digits.len(), WOTS_CHAINS);
        assert_eq!(&digits[..MESSAGE_DIGITS], &digest[..]);
        let mut checksum = 0_u16;
        for digit in digits.iter().take(MESSAGE_DIGITS) {
            checksum += 255_u16 - u16::from(*digit);
        }
        assert_eq!(
            digits.get(MESSAGE_DIGITS),
            Some(&u8::try_from(checksum >> 8).unwrap())
        );
        assert_eq!(
            digits.get(MESSAGE_DIGITS + 1),
            Some(&u8::try_from(checksum & 0xff).unwrap())
        );
    }

    #[test]
    fn public_api_kat_values() {
        let contexts = super::Qhs42Contexts::new();
        let sk = [1_u8; 32];
        let pk = [2_u8; 32];
        let wots = super::qhs42_wots_public_key(&sk, &pk, 0, 0, 0, &contexts);
        let leaf = super::qhs42_leaf(&sk, &pk, 0, 0, 0, &contexts);
        let fors_leaf = super::qhs42_fors_leaf(&sk, &pk, 0, 0, 0, 0, &contexts);
        assert_eq!(
            wots,
            [
                93, 76, 101, 128, 184, 179, 63, 68, 255, 223, 43, 77, 63, 245, 9, 117, 79, 194,
                169, 239, 79, 111, 108, 148, 68, 213, 137, 178, 103, 209, 224, 151
            ]
        );
        assert_eq!(
            leaf,
            [
                223, 60, 126, 124, 248, 0, 12, 93, 99, 135, 184, 253, 201, 140, 143, 178, 175, 51,
                35, 211, 62, 205, 43, 168, 224, 106, 0, 237, 47, 217, 254, 42
            ]
        );
        assert_eq!(
            fors_leaf,
            [
                59, 14, 81, 249, 165, 106, 195, 20, 154, 168, 72, 207, 227, 9, 73, 156, 227, 247,
                123, 155, 78, 138, 95, 51, 228, 109, 160, 237, 133, 175, 135, 67
            ]
        );

        let mut leaves = [[0_u8; 32]; LEAF_COUNT];
        for (index, slot) in leaves.iter_mut().enumerate() {
            let byte = u8::try_from(index).unwrap();
            *slot = [byte; 32];
        }
        let (root, auth) =
            super::qhs42_tree_root_and_auth_from_leaves(&leaves, 0, &contexts).unwrap();
        assert_eq!(
            root,
            [
                232, 201, 110, 154, 197, 112, 156, 52, 75, 170, 149, 255, 217, 79, 158, 225, 232,
                134, 26, 187, 181, 187, 118, 12, 59, 84, 201, 253, 218, 54, 189, 72
            ]
        );
        let tree_auth_bytes = super::auth_path_bytes(&auth).unwrap();
        assert_eq!(
            qwp_hash::hash32(&tree_auth_bytes).to_bytes(),
            [
                90, 249, 26, 160, 143, 43, 45, 58, 141, 125, 27, 115, 87, 211, 36, 109, 146, 124,
                99, 81, 103, 184, 144, 45, 251, 77, 68, 239, 128, 29, 129, 9
            ]
        );
        let tree = super::Qhs42Tree::new(root, auth);
        assert_eq!(tree.root(), root);
        assert_eq!(tree.auth_path(), &auth);

        let mut fors_leaves = [[0_u8; 32]; FORS_LEAVES];
        for (index, slot) in fors_leaves.iter_mut().enumerate() {
            let byte = u8::try_from(index).unwrap();
            *slot = [byte; 32];
        }
        let (fors_root, fors_auth) =
            super::qhs42_fors_root_and_auth_from_leaves(&fors_leaves, 0, &contexts).unwrap();
        assert_eq!(
            fors_root,
            [
                202, 64, 244, 167, 186, 75, 84, 254, 158, 51, 141, 48, 147, 165, 33, 85, 209, 72,
                126, 12, 164, 116, 195, 144, 224, 101, 93, 92, 173, 109, 245, 131
            ]
        );
        let fors_auth_bytes = super::auth_path_bytes(&fors_auth).unwrap();
        assert_eq!(
            qwp_hash::hash32(&fors_auth_bytes).to_bytes(),
            [
                109, 69, 29, 156, 37, 156, 174, 131, 173, 102, 1, 12, 120, 253, 195, 71, 18, 196,
                54, 182, 17, 241, 250, 240, 135, 143, 129, 246, 39, 226, 60, 185
            ]
        );
        let fors_tree = super::Qhs42ForsTree::new(fors_root, fors_auth);
        assert_eq!(fors_tree.root(), fors_root);
        assert_eq!(fors_tree.auth_path(), &fors_auth);

        let private_key = Qhs42PrivateKey::from_parts([3_u8; 32], [4_u8; 32]);
        let plan = super::qhs42_signing_plan(&private_key, b"qWp QHS-4.2 plan");
        assert_eq!(
            plan.randomizer(),
            [
                156, 249, 31, 63, 167, 150, 240, 254, 63, 208, 253, 109, 140, 31, 69, 204, 234,
                243, 219, 223, 136, 77, 5, 152, 107, 173, 81, 93, 13, 94, 45, 21
            ]
        );
        assert_eq!(
            plan.fors_digest(),
            [
                67, 170, 168, 213, 153, 140, 106, 22, 253, 82, 50, 31, 250, 59, 114, 45, 109, 14,
                57, 134, 96, 80, 99, 111, 104, 15, 121, 203, 157, 218, 102, 30
            ]
        );
        assert_eq!(plan.tree_index(), 11_828_721_361_547_899_209);
        assert_eq!(plan.bottom_tree(), 46_205_942_818_546_481);
        assert_eq!(plan.bottom_leaf(), 73);
        assert_eq!(plan.tree_indices().len(), LAYERS);
        assert_eq!(plan.leaf_indices().len(), LAYERS);
    }

    #[test]
    fn public_leaf_helpers_are_deterministic() {
        let contexts = super::Qhs42Contexts::default();
        let sk_seed = [1_u8; 32];
        let pk_seed = [2_u8; 32];
        let wots_pk = super::qhs42_wots_public_key(&sk_seed, &pk_seed, 0, 0, 0, &contexts);
        let leaf = super::qhs42_leaf(&sk_seed, &pk_seed, 0, 0, 0, &contexts);
        let fors_leaf = super::qhs42_fors_leaf(&sk_seed, &pk_seed, 0, 0, 0, 0, &contexts);
        assert_eq!(
            wots_pk,
            super::qhs42_wots_public_key(&sk_seed, &pk_seed, 0, 0, 0, &contexts)
        );
        assert_eq!(
            leaf,
            super::qhs42_leaf(&sk_seed, &pk_seed, 0, 0, 0, &contexts)
        );
        assert_eq!(
            fors_leaf,
            super::qhs42_fors_leaf(&sk_seed, &pk_seed, 0, 0, 0, 0, &contexts)
        );
        assert_ne!(wots_pk, [0_u8; 32]);
        assert_ne!(leaf, [0_u8; 32]);
        assert_ne!(fors_leaf, [0_u8; 32]);
        assert_ne!(wots_pk, leaf);
    }

    #[test]
    fn auth_path_bytes_rejects_wrong_length() {
        assert!(super::auth_path_bytes(&[]).is_err());
        assert!(super::auth_path_bytes(&[[0_u8; 32]; 7]).is_err());
        assert!(super::auth_path_bytes(&[[0_u8; 32]; 8]).is_ok());
    }

    #[test]
    fn wots_verify_rejects_wrong_length() {
        assert!(super::wots_verify(&[], &[0_u8; 32], &super::Qhs42Contexts::new()).is_err());
    }

    #[test]
    fn fors_verify_rejects_wrong_length() {
        assert!(super::fors_verify(&[0_u8; 32], &[], &super::Qhs42Contexts::new()).is_err());
    }

    #[test]
    fn climb_path_rejects_wrong_length() {
        assert!(
            super::climb_path([0_u8; 32], &[], 0, false, &super::Qhs42Contexts::new()).is_err()
        );
    }

    #[cfg(not(debug_assertions))]
    mod release {
        use crate::qhs42::{
            FORS_LEAVES, FORS_TREES, LAYERS, LEAF_COUNT, Qhs42Contexts, Qhs42ForsTree,
            Qhs42Signature, Qhs42Tree, keygen, qhs42_fors_leaf,
            qhs42_fors_root_and_auth_from_leaves, qhs42_leaf, qhs42_sign_with_trees,
            qhs42_signing_plan, qhs42_tree_root_and_auth_from_leaves,
        };
        use qwp_core::CryptoError;
        use qwp_hash::hash32;

        const SEED: [u8; 32] = [7_u8; 32];

        #[test]
        fn sign_verify_round_trip() {
            let (private_key, public_key) = keygen(&SEED).unwrap();
            let signature = private_key.sign(b"qWp QHS-4.2 message").unwrap();
            assert_eq!(
                public_key.verify(b"qWp QHS-4.2 message", &signature),
                Ok(())
            );
        }

        #[test]
        fn signature_layers_match_internal_derivation() {
            use crate::qhs42::{
                FORS_OFFSET, LAYER_BYTES, LAYER_OFFSET, WOTS_SIGNATURE_BYTES, auth_path_bytes,
                climb_path, derive_fors_digest, derive_randomizer, derive_tree_index,
                fors_public_key, fors_verify, layer_shift, leaf_hash, tree_root_and_auth,
                wots_sign, wots_verify,
            };

            let (private_key, _public_key) = keygen(&SEED).unwrap();
            let message = b"qWp QHS-4.2 layer debug";
            let randomizer = derive_randomizer(private_key.sk_seed(), message);
            let fors_digest = derive_fors_digest(&randomizer, private_key.pk_seed(), message);
            let tree_index = derive_tree_index(&randomizer, private_key.pk_seed(), message);
            let bottom_tree = tree_index.checked_shr(8).unwrap_or(0);
            let bottom_leaf = u8::try_from(tree_index & 0xff).unwrap();
            let contexts = Qhs42Contexts::new();
            let fors_pk_sign = fors_public_key(
                private_key.sk_seed(),
                private_key.pk_seed(),
                bottom_tree,
                bottom_leaf,
                &contexts,
            )
            .unwrap();
            let signature = private_key.sign(message).unwrap();
            let fors_sig = signature.as_bytes().get(FORS_OFFSET..LAYER_OFFSET).unwrap();
            let fors_pk_verify = fors_verify(&fors_digest, fors_sig, &contexts).unwrap();
            assert_eq!(fors_pk_sign, fors_pk_verify, "FORS mismatch");

            let mut previous_root = fors_pk_sign;
            for layer in 0..LAYERS {
                let shift = layer_shift(layer);
                let leaf_index =
                    u8::try_from(tree_index.checked_shr(shift).unwrap_or(0) & 0xff).unwrap();
                let tree_index_l = if layer == LAYERS - 1 {
                    0
                } else {
                    tree_index
                        .checked_shr(shift.checked_add(8).unwrap_or(0))
                        .unwrap_or(0)
                };
                let layer_u8 = u8::try_from(layer).unwrap();
                let (root, auth_path) = tree_root_and_auth(
                    private_key.sk_seed(),
                    private_key.pk_seed(),
                    layer_u8,
                    tree_index_l,
                    leaf_index,
                    &contexts,
                )
                .unwrap();
                let wots_sig = wots_sign(
                    private_key.sk_seed(),
                    private_key.pk_seed(),
                    layer_u8,
                    tree_index_l,
                    leaf_index,
                    &previous_root,
                    &contexts,
                )
                .unwrap();
                let wots_pk = wots_verify(&wots_sig, &previous_root, &contexts).unwrap();
                let leaf = leaf_hash(layer_u8, tree_index_l, leaf_index, &wots_pk, &contexts);
                let auth_bytes = auth_path_bytes(&auth_path).unwrap();
                let root_verify =
                    climb_path(leaf, &auth_bytes, leaf_index, false, &contexts).unwrap();
                assert_eq!(root, root_verify, "layer {layer} root mismatch");
                let offset = LAYER_OFFSET
                    .checked_add(layer.checked_mul(LAYER_BYTES).unwrap_or(0))
                    .unwrap();
                assert_eq!(
                    signature
                        .as_bytes()
                        .get(offset..offset + WOTS_SIGNATURE_BYTES),
                    Some(wots_sig.as_slice()),
                    "layer {layer} WOTS mismatch"
                );
                previous_root = root;
            }
        }

        #[test]
        fn deterministic_signatures() {
            let (private_key, public_key) = keygen(&SEED).unwrap();
            let first = private_key.sign(b"deterministic").unwrap();
            let second = private_key.sign(b"deterministic").unwrap();
            assert_eq!(first, second);
            assert_eq!(public_key.verify(b"deterministic", &first), Ok(()));
        }

        #[test]
        fn sign_with_trees_matches_sequential() {
            let (private_key, public_key) = keygen(&SEED).unwrap();
            let message = b"qWp QHS-4.2.1 equivalence";
            let sequential = private_key.sign(message).unwrap();
            let plan = qhs42_signing_plan(&private_key, message);
            let contexts = Qhs42Contexts::new();

            let mut hypertree = [Qhs42Tree::new([0_u8; 32], [[0_u8; 32]; 8]); LAYERS];
            for layer in 0..LAYERS {
                let tree_index_l = *plan.tree_indices().get(layer).unwrap();
                let leaf_index = *plan.leaf_indices().get(layer).unwrap();
                let mut leaves = [[0_u8; 32]; LEAF_COUNT];
                for (index, slot) in leaves.iter_mut().enumerate() {
                    let leaf = u8::try_from(index).unwrap();
                    *slot = qhs42_leaf(
                        private_key.sk_seed(),
                        private_key.pk_seed(),
                        u8::try_from(layer).unwrap(),
                        tree_index_l,
                        leaf,
                        &contexts,
                    );
                }
                let (root, auth_path) =
                    qhs42_tree_root_and_auth_from_leaves(&leaves, leaf_index, &contexts).unwrap();
                hypertree[layer] = Qhs42Tree::new(root, auth_path);
            }

            let mut fors = [Qhs42ForsTree::new([0_u8; 32], [[0_u8; 32]; 8]); FORS_TREES];
            for tree in 0..FORS_TREES {
                let selected = *plan.fors_digest().get(tree).unwrap();
                let mut leaves = [[0_u8; 32]; FORS_LEAVES];
                for (index, slot) in leaves.iter_mut().enumerate() {
                    let leaf = u8::try_from(index).unwrap();
                    *slot = qhs42_fors_leaf(
                        private_key.sk_seed(),
                        private_key.pk_seed(),
                        plan.bottom_tree(),
                        plan.bottom_leaf(),
                        u8::try_from(tree).unwrap(),
                        leaf,
                        &contexts,
                    );
                }
                let (root, auth_path) =
                    qhs42_fors_root_and_auth_from_leaves(&leaves, selected, &contexts).unwrap();
                fors[tree] = Qhs42ForsTree::new(root, auth_path);
            }

            let assembled =
                qhs42_sign_with_trees(&private_key, message, &plan, &hypertree, &fors).unwrap();
            assert_eq!(assembled, sequential);
            assert_eq!(public_key.verify(message, &assembled), Ok(()));

            let plan_again = qhs42_signing_plan(&private_key, message);
            assert_eq!(plan, plan_again);
            assert_eq!(plan.randomizer(), plan_again.randomizer());
            assert_eq!(plan.tree_index(), plan_again.tree_index());

            let mut wrong_hypertree = hypertree;
            wrong_hypertree[0] = Qhs42Tree::new([1_u8; 32], *hypertree[0].auth_path());
            assert_eq!(
                qhs42_sign_with_trees(&private_key, message, &plan, &wrong_hypertree, &fors),
                Err(CryptoError::InternalFailure)
            );

            let mut wrong_fors = fors;
            wrong_fors[0] = Qhs42ForsTree::new([1_u8; 32], *fors[0].auth_path());
            assert_eq!(
                qhs42_sign_with_trees(&private_key, message, &plan, &hypertree, &wrong_fors),
                Err(CryptoError::InternalFailure)
            );

            let wrong_plan = qhs42_signing_plan(&private_key, b"wrong");
            assert_eq!(
                qhs42_sign_with_trees(&private_key, message, &wrong_plan, &hypertree, &fors),
                Err(CryptoError::InternalFailure)
            );
        }

        #[test]
        fn rejects_wrong_message() {
            let (private_key, public_key) = keygen(&SEED).unwrap();
            let signature = private_key.sign(b"message-a").unwrap();
            assert_eq!(
                public_key.verify(b"message-b", &signature),
                Err(CryptoError::VerificationFailed)
            );
        }

        #[test]
        fn rejects_wrong_key() {
            let (private_key, _) = keygen(&SEED).unwrap();
            let (_, other_public_key) = keygen(&[9_u8; 32]).unwrap();
            let signature = private_key.sign(b"message").unwrap();
            assert_eq!(
                other_public_key.verify(b"message", &signature),
                Err(CryptoError::VerificationFailed)
            );
        }

        #[test]
        fn rejects_tampered_signature() {
            let (private_key, public_key) = keygen(&SEED).unwrap();
            let signature = private_key.sign(b"message").unwrap();
            let mut bytes = signature.to_bytes();
            if let Some(byte) = bytes.get_mut(crate::qhs42::FORS_OFFSET + 10) {
                *byte ^= 1;
            }
            let tampered = Qhs42Signature::from_bytes(bytes);
            assert_eq!(
                public_key.verify(b"message", &tampered),
                Err(CryptoError::VerificationFailed)
            );
        }

        #[test]
        fn known_answer_signature_hash() {
            let (private_key, _) = keygen(&SEED).unwrap();
            let signature = private_key.sign(b"qWp QHS-4.2 KAT").unwrap();
            assert_eq!(
                std::format!("{:?}", hash32(&signature.to_bytes())),
                "Hash32(0c97abdbd5221ab0d589873abdc6d1ed4f80b8a3bcbeab1cf8f05cd33f362ca2)"
            );
        }
    }
}
