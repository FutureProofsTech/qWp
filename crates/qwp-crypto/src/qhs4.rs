//! QHS-4: stateless hypertree/FORS signature.
//!
//! QHS-4 uses a FORS few-time signature at the bottom of an 8-layer hypertree
//! of WOTS keys. It has no state counter and no cache. The proof is in
//! `docs/13-qhs4.md`.

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
/// Bytes in a WOTS signature.
const WOTS_SIGNATURE_BYTES: usize = WOTS_CHAINS * 32;
/// Hypertree subtree height.
const TREE_HEIGHT: usize = 8;
/// Number of leaves in a hypertree subtree.
const LEAF_COUNT: usize = 256;
/// Bytes in a subtree authentication path.
const AUTH_PATH_BYTES: usize = TREE_HEIGHT * 32;
/// Number of hypertree layers.
const LAYERS: usize = 8;
/// Total hypertree height.
const TOTAL_HEIGHT: usize = 64;
/// Number of FORS trees.
const FORS_TREES: usize = 16;
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
const KEY_HEADER: [u8; HEADER_BYTES] = [4, 4, 64, 0];

/// QHS-4 public key size.
pub const QHS4_PUBLIC_KEY_BYTES: usize = 68;
/// QHS-4 private key size.
pub const QHS4_PRIVATE_KEY_BYTES: usize = 68;
/// QHS-4 signature size.
pub const QHS4_SIGNATURE_BYTES: usize = CHECKSUM_OFFSET + CHECKSUM_BYTES;
/// QHS-4 total hypertree height.
pub const QHS4_TOTAL_HEIGHT: usize = TOTAL_HEIGHT;
/// QHS-4 FORS signature size.
pub const QHS4_FORS_BYTES: usize = FORS_SIGNATURE_BYTES;

const SK_SEED_CONTEXT: &[u8] = b"qWp QHS-4 sk seed";
const PK_SEED_CONTEXT: &[u8] = b"qWp QHS-4 pk seed";
const RANDOMIZER_CONTEXT: &[u8] = b"qWp QHS-4 randomizer";
const FORS_DIGEST_CONTEXT: &[u8] = b"qWp QHS-4 fors digest";
const TREE_INDEX_CONTEXT: &[u8] = b"qWp QHS-4 tree index";
const WOTS_SECRET_CONTEXT: &[u8] = b"qWp QHS-4 wots secret";
const CHAIN_CONTEXT: &[u8] = b"qWp QHS-4 chain";
const WOTS_MESSAGE_CONTEXT: &[u8] = b"qWp QHS-4 wots message";
const WOTS_PK_CONTEXT: &[u8] = b"qWp QHS-4 wots-pk";
const LEAF_CONTEXT: &[u8] = b"qWp QHS-4 leaf";
const NODE_CONTEXT: &[u8] = b"qWp QHS-4 node";
const FORS_SECRET_CONTEXT: &[u8] = b"qWp QHS-4 fors secret";
const FORS_LEAF_CONTEXT: &[u8] = b"qWp QHS-4 fors leaf";
const FORS_NODE_CONTEXT: &[u8] = b"qWp QHS-4 fors node";
const FORS_PK_CONTEXT: &[u8] = b"qWp QHS-4 fors-pk";
const CHECKSUM_CONTEXT: &[u8] = b"qWp QHS-4 signature-checksum";

/// A QHS-4 public key: `PK.seed` and a hypertree root.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs4PublicKey {
    bytes: [u8; QHS4_PUBLIC_KEY_BYTES],
}

impl Qhs4PublicKey {
    /// Creates a public key from `PK.seed` and a hypertree root.
    #[must_use]
    #[inline]
    pub fn from_root(pk_seed: [u8; 32], root: [u8; 32]) -> Self {
        let mut bytes = [0_u8; QHS4_PUBLIC_KEY_BYTES];
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
    pub fn from_bytes(bytes: &[u8; QHS4_PUBLIC_KEY_BYTES]) -> Result<Self, CryptoError> {
        let header = bytes
            .get(0..HEADER_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        if header != KEY_HEADER.as_slice() {
            return Err(CryptoError::InvalidLength);
        }
        let mut output = [0_u8; QHS4_PUBLIC_KEY_BYTES];
        output.copy_from_slice(bytes);
        Ok(Self { bytes: output })
    }

    /// Returns the exact 68-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS4_PUBLIC_KEY_BYTES] {
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

    /// Verifies a QHS-4 signature.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::VerificationFailed`] for an invalid signature.
    #[inline]
    pub fn verify(&self, message: &[u8], signature: &Qhs4Signature) -> Result<(), CryptoError> {
        let bytes = signature.as_bytes();
        let header = bytes
            .get(0..HEADER_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        if header != KEY_HEADER.as_slice() {
            return Err(CryptoError::VerificationFailed);
        }
        let body = bytes
            .get(..CHECKSUM_BODY_BYTES)
            .ok_or(CryptoError::VerificationFailed)?;
        let expected_checksum = signature_checksum(body)?;
        let actual_checksum = bytes
            .get(CHECKSUM_OFFSET..QHS4_SIGNATURE_BYTES)
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
            let wots_pk = wots_verify(wots_signature, &previous_root)?;
            let leaf = leaf_hash(
                u8::try_from(layer).unwrap_or(0),
                tree_index_l,
                leaf_index,
                &wots_pk,
            );
            previous_root = climb_path(leaf, auth_path, leaf_index, false)?;
        }

        if previous_root == self.root() {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

/// A QHS-4 private key.
///
/// The key is stateless: signing never changes it. It is not `Clone`, is not
/// printable, and is wiped best-effort on drop.
pub struct Qhs4PrivateKey {
    header: [u8; HEADER_BYTES],
    sk_seed: [u8; 32],
    pk_seed: [u8; 32],
}

impl Qhs4PrivateKey {
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
    pub fn from_bytes(bytes: &[u8; QHS4_PRIVATE_KEY_BYTES]) -> Result<Self, CryptoError> {
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
    pub fn to_bytes(&self) -> [u8; QHS4_PRIVATE_KEY_BYTES] {
        let mut bytes = [0_u8; QHS4_PRIVATE_KEY_BYTES];
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
        reason = "the fixed QHS-4 signature is 18,216 bytes and this crate is no_std"
    )]
    pub fn sign(&self, message: &[u8]) -> Result<Qhs4Signature, CryptoError> {
        let randomizer = derive_randomizer(&self.sk_seed, message);
        let fors_digest = derive_fors_digest(&randomizer, &self.pk_seed, message);
        let tree_index = derive_tree_index(&randomizer, &self.pk_seed, message);
        let bottom_leaf = u8::try_from(tree_index & 0xff).unwrap_or(0);
        let bottom_tree = tree_index.checked_shr(8).unwrap_or(0);

        let fors_pk = fors_public_key(&self.sk_seed, &self.pk_seed, bottom_tree, bottom_leaf)?;
        let mut signature = Qhs4Signature {
            bytes: [0_u8; QHS4_SIGNATURE_BYTES],
        };
        write_header(&mut signature, &randomizer)?;
        write_fors_signature(
            &mut signature,
            &self.sk_seed,
            &self.pk_seed,
            bottom_tree,
            bottom_leaf,
            &fors_digest,
        )?;
        write_hypertree(
            &mut signature,
            &self.sk_seed,
            &self.pk_seed,
            tree_index,
            fors_pk,
        )?;
        write_checksum(&mut signature)?;
        Ok(signature)
    }
}

fn write_header(signature: &mut Qhs4Signature, randomizer: &[u8; 32]) -> Result<(), CryptoError> {
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
    signature: &mut Qhs4Signature,
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    bottom_tree: u64,
    bottom_leaf: u8,
    fors_digest: &[u8; 32],
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
        );
        let (_, auth_path) = fors_root_and_auth(
            sk_seed,
            pk_seed,
            bottom_tree,
            bottom_leaf,
            tree_u8,
            selected,
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
    signature: &mut Qhs4Signature,
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    tree_index: u64,
    fors_pk: [u8; 32],
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
        )?;
        let (root, auth_path) =
            tree_root_and_auth(sk_seed, pk_seed, layer_u8, tree_index_l, leaf_index)?;
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

fn write_checksum(signature: &mut Qhs4Signature) -> Result<(), CryptoError> {
    let body = signature
        .bytes
        .get(..CHECKSUM_BODY_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    let checksum = signature_checksum(body)?;
    let slot = signature
        .bytes
        .get_mut(CHECKSUM_OFFSET..QHS4_SIGNATURE_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    slot.copy_from_slice(&checksum);
    Ok(())
}

impl Drop for Qhs4PrivateKey {
    #[inline]
    fn drop(&mut self) {
        self.header.fill(0);
        self.sk_seed.fill(0);
        self.pk_seed.fill(0);
    }
}

impl fmt::Debug for Qhs4PrivateKey {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Qhs4PrivateKey")
            .finish_non_exhaustive()
    }
}

/// A QHS-4 signature.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qhs4Signature {
    bytes: [u8; QHS4_SIGNATURE_BYTES],
}

impl Qhs4Signature {
    /// Creates a signature from its exact 18,216-byte representation.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; QHS4_SIGNATURE_BYTES]) -> Self {
        Self { bytes }
    }

    /// Parses a signature from a byte slice of exactly 18,216 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] for any other length.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; QHS4_SIGNATURE_BYTES] =
            bytes.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self { bytes: array })
    }

    /// Returns the exact 18,216-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; QHS4_SIGNATURE_BYTES] {
        self.bytes
    }

    /// Returns the signature bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; QHS4_SIGNATURE_BYTES] {
        &self.bytes
    }
}

/// Generates a QHS-4 key pair from a 32-byte seed.
///
/// # Errors
///
/// Returns an internal error if a fixed-size layout is malformed.
#[inline]
pub fn keygen(seed: &[u8; 32]) -> Result<(Qhs4PrivateKey, Qhs4PublicKey), CryptoError> {
    let sk_seed = derive_key32(SK_SEED_CONTEXT, seed).to_bytes();
    let pk_seed = derive_key32(PK_SEED_CONTEXT, seed).to_bytes();
    let (root, _) = tree_root_and_auth(&sk_seed, &pk_seed, 7, 0, 0)?;
    Ok((
        Qhs4PrivateKey::from_parts(sk_seed, pk_seed),
        Qhs4PublicKey::from_root(pk_seed, root),
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
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(WOTS_SECRET_CONTEXT);
    hasher.update(sk_seed);
    hasher.update(pk_seed);
    hasher.update(&[layer]);
    hasher.update(&tree_index.to_le_bytes());
    hasher.update(&[leaf_index, chain_index]);
    hasher.finalize().to_bytes()
}

fn chain_hash(value: &[u8; 32]) -> [u8; 32] {
    derive_key32(CHAIN_CONTEXT, value).to_bytes()
}

fn wots_pk_hash(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(WOTS_PK_CONTEXT);
    for chain_index in 0..WOTS_CHAINS {
        let chain_u8 = u8::try_from(chain_index).unwrap_or(0);
        let mut value = wots_secret(sk_seed, pk_seed, layer, tree_index, leaf_index, chain_u8);
        for _ in 0..WOTS_CHAIN_LEN {
            value = chain_hash(&value);
        }
        hasher.update(&value);
    }
    hasher.finalize().to_bytes()
}

fn leaf_hash(layer: u8, tree_index: u64, leaf_index: u8, wots_pk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(LEAF_CONTEXT);
    hasher.update(&[layer]);
    hasher.update(&tree_index.to_le_bytes());
    hasher.update(&[leaf_index]);
    hasher.update(wots_pk);
    hasher.finalize().to_bytes()
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

fn tree_root_and_auth(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
) -> Result<([u8; 32], [[u8; 32]; TREE_HEIGHT]), CryptoError> {
    let mut nodes = [[0_u8; 32]; LEAF_COUNT];
    for (index, slot) in nodes.iter_mut().enumerate() {
        let leaf = u8::try_from(index).map_err(|_| CryptoError::InvalidLength)?;
        let wots_pk = wots_pk_hash(sk_seed, pk_seed, layer, tree_index, leaf);
        *slot = leaf_hash(layer, tree_index, leaf, &wots_pk);
    }

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

    let root = nodes.first().copied().ok_or(CryptoError::InvalidLength)?;
    Ok((root, path))
}

fn climb_path(
    mut node: [u8; 32],
    auth_path: &[u8],
    leaf_index: u8,
    fors: bool,
) -> Result<[u8; 32], CryptoError> {
    if auth_path.len() != AUTH_PATH_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    for (level, sibling) in auth_path.as_chunks::<32>().0.iter().enumerate() {
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let bit = usize::from(leaf_index).checked_shr(level_u32).unwrap_or(0) & 1;
        node = if bit == 0 {
            if fors {
                fors_node_hash(&node, sibling)
            } else {
                node_hash(&node, sibling)
            }
        } else if fors {
            fors_node_hash(sibling, &node)
        } else {
            node_hash(sibling, &node)
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
) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(FORS_SECRET_CONTEXT);
    hasher.update(sk_seed);
    hasher.update(pk_seed);
    hasher.update(&tree_index.to_le_bytes());
    hasher.update(&[leaf_index, fors_tree, fors_leaf]);
    hasher.finalize().to_bytes()
}

fn fors_leaf_hash(fors_tree: u8, fors_leaf: u8, secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new_derive_key(FORS_LEAF_CONTEXT);
    hasher.update(&[fors_tree, fors_leaf]);
    hasher.update(secret);
    hasher.finalize().to_bytes()
}

fn fors_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 64];
    if let Some(slot) = input.get_mut(0..32) {
        slot.copy_from_slice(left);
    }
    if let Some(slot) = input.get_mut(32..64) {
        slot.copy_from_slice(right);
    }
    derive_key32(FORS_NODE_CONTEXT, &input).to_bytes()
}

fn fors_root_and_auth(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    tree_index: u64,
    leaf_index: u8,
    fors_tree: u8,
    selected: u8,
) -> Result<([u8; 32], [[u8; 32]; FORS_HEIGHT]), CryptoError> {
    let mut nodes = [[0_u8; 32]; FORS_LEAVES];
    for (index, slot) in nodes.iter_mut().enumerate() {
        let leaf = u8::try_from(index).map_err(|_| CryptoError::InvalidLength)?;
        let secret = fors_secret(sk_seed, pk_seed, tree_index, leaf_index, fors_tree, leaf);
        *slot = fors_leaf_hash(fors_tree, leaf, &secret);
    }

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
            let parent = fors_node_hash(&left, &right);
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
) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Hasher::new_derive_key(FORS_PK_CONTEXT);
    for fors_tree in 0..FORS_TREES {
        let tree_u8 = u8::try_from(fors_tree).unwrap_or(0);
        let (root, _) = fors_root_and_auth(sk_seed, pk_seed, tree_index, leaf_index, tree_u8, 0)?;
        hasher.update(&root);
    }
    Ok(hasher.finalize().to_bytes())
}

fn fors_verify(digest: &[u8; 32], signature: &[u8]) -> Result<[u8; 32], CryptoError> {
    if signature.len() != FORS_SIGNATURE_BYTES {
        return Err(CryptoError::VerificationFailed);
    }
    let mut hasher = Hasher::new_derive_key(FORS_PK_CONTEXT);
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
        let leaf = fors_leaf_hash(u8::try_from(fors_tree).unwrap_or(0), selected, &secret);
        let root = climb_path(leaf, auth_path, selected, true)?;
        hasher.update(&root);
    }
    Ok(hasher.finalize().to_bytes())
}

fn message_digits(message: &[u8; 32]) -> [u8; WOTS_CHAINS] {
    let digest = derive_key32(WOTS_MESSAGE_CONTEXT, message).to_bytes();
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
                let shift = 7_u32.saturating_sub(
                    u32::try_from(digest_bit.checked_rem(8).unwrap_or(0)).unwrap_or(0),
                );
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
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer: u8,
    tree_index: u64,
    leaf_index: u8,
    message: &[u8; 32],
) -> Result<[u8; WOTS_SIGNATURE_BYTES], CryptoError> {
    let digits = message_digits(message);
    let mut signature = [0_u8; WOTS_SIGNATURE_BYTES];
    for (chain_index, (slot, digit)) in signature
        .as_chunks_mut::<32>()
        .0
        .iter_mut()
        .zip(digits.iter())
        .enumerate()
    {
        let chain_u8 = u8::try_from(chain_index).map_err(|_| CryptoError::InvalidLength)?;
        let mut value = wots_secret(sk_seed, pk_seed, layer, tree_index, leaf_index, chain_u8);
        for _ in 0..*digit {
            value = chain_hash(&value);
        }
        slot.copy_from_slice(&value);
    }
    Ok(signature)
}

fn wots_verify(signature: &[u8], message: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    if signature.len() != WOTS_SIGNATURE_BYTES {
        return Err(CryptoError::VerificationFailed);
    }
    let digits = message_digits(message);
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

fn signature_checksum(body: &[u8]) -> Result<[u8; CHECKSUM_BYTES], CryptoError> {
    let hash = derive_key32(CHECKSUM_CONTEXT, body);
    let mut checksum = [0_u8; CHECKSUM_BYTES];
    let source = hash
        .as_bytes()
        .get(..CHECKSUM_BYTES)
        .ok_or(CryptoError::InvalidLength)?;
    checksum.copy_from_slice(source);
    Ok(checksum)
}

const _: [(); QHS4_PUBLIC_KEY_BYTES] = [(); size_of::<Qhs4PublicKey>()];
const _: [(); QHS4_PRIVATE_KEY_BYTES] = [(); size_of::<Qhs4PrivateKey>()];
const _: [(); QHS4_SIGNATURE_BYTES] = [(); size_of::<Qhs4Signature>()];
const _: [(); 18_216] = [(); QHS4_SIGNATURE_BYTES];
const _: [(); 64] = [(); TOTAL_HEIGHT];

#[cfg(test)]
mod tests {
    #![allow(
        clippy::large_stack_arrays,
        clippy::std_instead_of_alloc,
        reason = "tests use the fixed QHS-4 signature size and std for formatting"
    )]

    use super::{
        CHAIN_CONTEXT, CHECKSUM_CONTEXT, FORS_DIGEST_CONTEXT, FORS_LEAF_CONTEXT, FORS_NODE_CONTEXT,
        FORS_PK_CONTEXT, FORS_SECRET_CONTEXT, LEAF_CONTEXT, MESSAGE_DIGITS, NODE_CONTEXT,
        PK_SEED_CONTEXT, QHS4_FORS_BYTES, QHS4_SIGNATURE_BYTES, Qhs4PrivateKey, Qhs4PublicKey,
        Qhs4Signature, RANDOMIZER_CONTEXT, SK_SEED_CONTEXT, TREE_INDEX_CONTEXT, WOTS_CHAINS,
        WOTS_MESSAGE_CONTEXT, WOTS_PK_CONTEXT, WOTS_SECRET_CONTEXT,
    };
    use core::mem::size_of;
    use qwp_core::CryptoError;

    #[test]
    fn signature_size_is_exact() {
        assert_eq!(size_of::<Qhs4Signature>(), QHS4_SIGNATURE_BYTES);
        assert_eq!(QHS4_SIGNATURE_BYTES, 18_216);
        assert_eq!(QHS4_FORS_BYTES, 4_608);
    }

    #[test]
    fn public_key_round_trip() {
        let public_key = Qhs4PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let bytes = public_key.to_bytes();
        assert_eq!(Qhs4PublicKey::from_bytes(&bytes), Ok(public_key));
        assert_eq!(public_key.seed(), [1_u8; 32]);
        assert_eq!(public_key.root(), [2_u8; 32]);
    }

    #[test]
    fn public_key_rejects_bad_header() {
        let public_key = Qhs4PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let original = public_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs4PublicKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn private_key_round_trip() {
        let private_key = Qhs4PrivateKey::from_parts([1_u8; 32], [2_u8; 32]);
        let bytes = private_key.to_bytes();
        assert_eq!(&bytes[..4], &[4, 4, 64, 0]);
        assert_eq!(&bytes[4..36], &[1_u8; 32]);
        assert_eq!(&bytes[36..68], &[2_u8; 32]);
        let parsed = Qhs4PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sk_seed(), &[1_u8; 32]);
        assert_eq!(parsed.pk_seed(), &[2_u8; 32]);
    }

    #[test]
    fn private_key_rejects_bad_header() {
        let private_key = Qhs4PrivateKey::from_parts([1_u8; 32], [2_u8; 32]);
        let original = private_key.to_bytes();
        for index in 0..4 {
            let mut bytes = original;
            if let Some(byte) = bytes.get_mut(index) {
                *byte ^= 1;
            }
            assert!(Qhs4PrivateKey::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let private_key = Qhs4PrivateKey::from_parts([1_u8; 32], [2_u8; 32]);
        let debug = std::format!("{private_key:?}");
        assert!(debug.contains("Qhs4PrivateKey"));
        assert!(!debug.contains("seed"));
    }

    #[test]
    fn signature_round_trip_and_slice() {
        let signature = Qhs4Signature::from_bytes([3_u8; QHS4_SIGNATURE_BYTES]);
        let bytes = signature.to_bytes();
        assert_eq!(Qhs4Signature::from_slice(&bytes), Ok(signature));
        assert!(Qhs4Signature::from_slice(&bytes[..QHS4_SIGNATURE_BYTES - 1]).is_err());
    }

    #[test]
    fn verify_rejects_zero_signature() {
        let public_key = Qhs4PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let signature = Qhs4Signature::from_bytes([0_u8; QHS4_SIGNATURE_BYTES]);
        assert_eq!(
            public_key.verify(b"message", &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn verify_rejects_bad_header_with_valid_checksum() {
        let public_key = Qhs4PublicKey::from_root([1_u8; 32], [2_u8; 32]);
        let mut bytes = [0_u8; QHS4_SIGNATURE_BYTES];
        if let Some(header) = bytes.get_mut(0..4) {
            header.copy_from_slice(&[3, 4, 64, 0]);
        }
        let body = bytes.get(..super::CHECKSUM_BODY_BYTES).unwrap();
        let checksum = super::signature_checksum(body).unwrap();
        if let Some(slot) = bytes.get_mut(super::CHECKSUM_OFFSET..) {
            slot.copy_from_slice(&checksum);
        }
        let signature = Qhs4Signature::from_bytes(bytes);
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
        let digits = super::message_digits(&message);
        assert_eq!(digits.len(), WOTS_CHAINS);
        assert!(digits.first().is_some_and(|digit| *digit < 16));
        assert!(digits.iter().all(|digit| *digit < 64));
        let mut checksum = 0_u16;
        for digit in digits.iter().take(MESSAGE_DIGITS) {
            checksum += 63_u16 - u16::from(*digit);
        }
        assert_eq!(
            digits.get(MESSAGE_DIGITS),
            Some(&u8::try_from(checksum >> 6).unwrap())
        );
        assert_eq!(
            digits.get(MESSAGE_DIGITS + 1),
            Some(&u8::try_from(checksum & 0x3f).unwrap())
        );
    }

    #[test]
    fn wots_verify_rejects_wrong_length() {
        assert!(super::wots_verify(&[], &[0_u8; 32]).is_err());
    }

    #[test]
    fn fors_verify_rejects_wrong_length() {
        assert!(super::fors_verify(&[0_u8; 32], &[]).is_err());
    }

    #[test]
    fn climb_path_rejects_wrong_length() {
        assert!(super::climb_path([0_u8; 32], &[], 0, false).is_err());
    }

    #[cfg(not(debug_assertions))]
    mod release {
        use crate::qhs4::{Qhs4Signature, keygen};
        use qwp_core::CryptoError;
        use qwp_hash::hash32;

        const SEED: [u8; 32] = [7_u8; 32];

        #[test]
        fn sign_verify_round_trip() {
            let (private_key, public_key) = keygen(&SEED).unwrap();
            let signature = private_key.sign(b"qWp QHS-4 message").unwrap();
            assert_eq!(public_key.verify(b"qWp QHS-4 message", &signature), Ok(()));
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
            if let Some(byte) = bytes.get_mut(crate::qhs4::FORS_OFFSET + 10) {
                *byte ^= 1;
            }
            let tampered = Qhs4Signature::from_bytes(bytes);
            assert_eq!(
                public_key.verify(b"message", &tampered),
                Err(CryptoError::VerificationFailed)
            );
        }

        #[test]
        fn known_answer_signature_hash() {
            let (private_key, _) = keygen(&SEED).unwrap();
            let signature = private_key.sign(b"qWp QHS-4 KAT").unwrap();
            assert_eq!(
                std::format!("{:?}", hash32(&signature.to_bytes())),
                "Hash32(43669f2fe1a86fcc52d2dbcc57e172917bc6ea9189b3404ffa9e1a046e8b1f95)"
            );
        }
    }
}
