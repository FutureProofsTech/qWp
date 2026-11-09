//! qWp safe platform adapters.
//!
//! The Unix host adapter reads `/dev/urandom` through `std::fs`; there is no
//! external entropy crate and no first-party `unsafe`.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "qWp is local-only; release metadata is finalized at packaging time"
)]
#![allow(
    clippy::std_instead_of_core,
    reason = "the host platform adapter intentionally uses std::fs and std::io"
)]
#![deny(clippy::alloc_instead_of_core)]
#![deny(clippy::std_instead_of_alloc)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unreachable)]
#![deny(clippy::as_conversions)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::missing_inline_in_public_items)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::panic_in_result_fn)]
#![deny(clippy::unwrap_in_result)]
#![deny(clippy::allow_attributes_without_reason)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::exit)]
#![deny(clippy::mem_forget)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::let_underscore_must_use)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(rustdoc::all)]
#![deny(unreachable_pub)]
#![deny(unused_results)]
#![deny(let_underscore_drop)]
#![deny(non_ascii_idents)]
#![deny(rust_2018_idioms)]
#![deny(future_incompatible)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![deny(unused_qualifications)]
#![deny(unused_lifetimes)]
#![deny(single_use_lifetimes)]
#![deny(elided_lifetimes_in_paths)]
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_lossless,
        reason = "tests may assert, index fixed arrays, and use small numeric conversions"
    )
)]

use core::fmt;
use std::fs::File;
use std::io::Read;

use qwp_core::CryptoError;
use qwp_crypto::{
    QHS_LEAF_COUNT, QHS2_LEAF_COUNT, QHS3_LEAF_COUNT, QHS4_FORS_HEIGHT, QHS4_FORS_LEAVES,
    QHS4_FORS_TREES, QHS4_LAYERS, QHS4_LEAF_COUNT, QHS4_TREE_HEIGHT, Qhs4Contexts, Qhs4ForsTree,
    Qhs4PrivateKey, Qhs4Signature, Qhs4Tree, qhs_leaf, qhs2_leaf, qhs3_leaf, qhs4_fors_leaf,
    qhs4_fors_root_and_auth_from_leaves, qhs4_leaf, qhs4_sign_with_trees, qhs4_signing_plan,
    qhs4_tree_root_and_auth_from_leaves,
};

const QHS4_HYPERTREE_LEAF_TOTAL: usize = QHS4_LAYERS * QHS4_LEAF_COUNT;
const QHS4_FORS_LEAF_TOTAL: usize = QHS4_FORS_TREES * QHS4_FORS_LEAVES;

/// A safe host entropy source backed by `/dev/urandom`.
pub struct HostEntropy {
    file: File,
}

impl HostEntropy {
    /// Opens the host entropy source.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyFailure`] when `/dev/urandom` cannot be
    /// opened, and [`CryptoError::UnsupportedPlatform`] on non-Unix hosts.
    #[inline]
    pub fn open() -> Result<Self, CryptoError> {
        #[cfg(unix)]
        {
            let file = File::open("/dev/urandom").map_err(|_| CryptoError::EntropyFailure)?;
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        {
            Err(CryptoError::UnsupportedPlatform)
        }
    }

    /// Fills `output` with host entropy.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EntropyFailure`] when the read fails.
    #[inline]
    pub fn fill(&mut self, output: &mut [u8]) -> Result<(), CryptoError> {
        self.file
            .read_exact(output)
            .map_err(|_| CryptoError::EntropyFailure)
    }
}

impl fmt::Debug for HostEntropy {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostEntropy")
            .finish_non_exhaustive()
    }
}

/// Computes QHS-1 Merkle leaves in parallel on the host.
///
/// This is a performance API. The leaves are identical to the sequential
/// derivation and contain no secret WOTS values.
///
/// # Errors
///
/// Returns an internal error if a worker fails or a leaf index is invalid.
#[inline]
pub fn qhs_leaves_parallel(seed: &[u8; 32]) -> Result<[[u8; 32]; QHS_LEAF_COUNT], CryptoError> {
    let mut leaves = [[0_u8; 32]; QHS_LEAF_COUNT];
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(16);
    let chunk_size = QHS_LEAF_COUNT.div_ceil(threads);

    std::thread::scope(|scope| -> Result<(), CryptoError> {
        let mut handles = Vec::new();
        for (chunk_index, chunk) in leaves.chunks_mut(chunk_size).enumerate() {
            let base = chunk_index.checked_mul(chunk_size).unwrap_or(0);
            handles.push(scope.spawn(move || -> Result<(), CryptoError> {
                for (offset, slot) in chunk.iter_mut().enumerate() {
                    let index = u16::try_from(base.checked_add(offset).unwrap_or(0))
                        .map_err(|_| CryptoError::InvalidLength)?;
                    *slot = qhs_leaf(seed, index)?;
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| CryptoError::InternalFailure)??;
        }
        Ok(())
    })?;

    Ok(leaves)
}

/// Computes QHS-2 Merkle leaves in parallel on the host.
///
/// This is a performance API. The leaves are identical to the sequential
/// derivation and contain no secret WOTS values.
///
/// # Errors
///
/// Returns an internal error if a worker fails or a leaf index is invalid.
#[inline]
pub fn qhs2_leaves_parallel(seed: &[u8; 32]) -> Result<[[u8; 32]; QHS2_LEAF_COUNT], CryptoError> {
    let mut leaves = [[0_u8; 32]; QHS2_LEAF_COUNT];
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(16);
    let chunk_size = QHS2_LEAF_COUNT.div_ceil(threads);

    std::thread::scope(|scope| -> Result<(), CryptoError> {
        let mut handles = Vec::new();
        for (chunk_index, chunk) in leaves.chunks_mut(chunk_size).enumerate() {
            let base = chunk_index.checked_mul(chunk_size).unwrap_or(0);
            handles.push(scope.spawn(move || -> Result<(), CryptoError> {
                for (offset, slot) in chunk.iter_mut().enumerate() {
                    let index = u16::try_from(base.checked_add(offset).unwrap_or(0))
                        .map_err(|_| CryptoError::InvalidLength)?;
                    *slot = qhs2_leaf(seed, index)?;
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| CryptoError::InternalFailure)??;
        }
        Ok(())
    })?;

    Ok(leaves)
}

/// Computes QHS-3 Merkle leaves in parallel on the host.
///
/// This is a performance API. The leaves are identical to the sequential
/// derivation and contain no secret WOTS values.
///
/// # Errors
///
/// Returns an internal error if a worker fails or a leaf index is invalid.
#[inline]
pub fn qhs3_leaves_parallel(seed: &[u8; 32]) -> Result<Vec<[u8; 32]>, CryptoError> {
    let mut leaves = vec![[0_u8; 32]; QHS3_LEAF_COUNT];
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(16);
    let chunk_size = QHS3_LEAF_COUNT.div_ceil(threads);

    std::thread::scope(|scope| -> Result<(), CryptoError> {
        let mut handles = Vec::new();
        for (chunk_index, chunk) in leaves.chunks_mut(chunk_size).enumerate() {
            let base = chunk_index.checked_mul(chunk_size).unwrap_or(0);
            handles.push(scope.spawn(move || -> Result<(), CryptoError> {
                for (offset, slot) in chunk.iter_mut().enumerate() {
                    let index = u16::try_from(base.checked_add(offset).unwrap_or(0))
                        .map_err(|_| CryptoError::InvalidLength)?;
                    *slot = qhs3_leaf(seed, index)?;
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| CryptoError::InternalFailure)??;
        }
        Ok(())
    })?;

    Ok(leaves)
}

fn parallel_fill<F>(output: &mut [[u8; 32]], threads: usize, compute: F) -> Result<(), CryptoError>
where
    F: Fn(usize) -> Result<[u8; 32], CryptoError> + Sync,
{
    if output.is_empty() || threads == 0 {
        return Ok(());
    }
    let chunk_size = output.len().div_ceil(threads);
    std::thread::scope(|scope| -> Result<(), CryptoError> {
        let mut handles = Vec::new();
        for (chunk_index, chunk) in output.chunks_mut(chunk_size).enumerate() {
            let base = chunk_index.checked_mul(chunk_size).unwrap_or(0);
            let compute = &compute;
            handles.push(scope.spawn(move || -> Result<(), CryptoError> {
                for (offset, slot) in chunk.iter_mut().enumerate() {
                    *slot = compute(base.checked_add(offset).unwrap_or(0))?;
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| CryptoError::InternalFailure)??;
        }
        Ok(())
    })
}

/// Signs a message with QHS-4 using parallel tree generation.
///
/// The returned signature is byte-identical to [`Qhs4PrivateKey::sign`].
///
/// # Errors
///
/// Returns an internal error if a worker fails or a tree layout is malformed.
#[inline]
pub fn qhs4_sign_parallel(
    private_key: &Qhs4PrivateKey,
    message: &[u8],
) -> Result<Qhs4Signature, CryptoError> {
    let plan = qhs4_signing_plan(private_key, message);
    let contexts = Qhs4Contexts::new();
    let sk_seed = private_key.sk_seed();
    let pk_seed = private_key.pk_seed();
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(16);

    let mut hypertree_leaves = vec![[0_u8; 32]; QHS4_HYPERTREE_LEAF_TOTAL];
    let tree_indices = *plan.tree_indices();
    parallel_fill(&mut hypertree_leaves, threads, |index| {
        let layer = index.checked_div(QHS4_LEAF_COUNT).unwrap_or(0);
        let leaf = index.checked_rem(QHS4_LEAF_COUNT).unwrap_or(0);
        let layer_u8 = u8::try_from(layer).map_err(|_| CryptoError::InternalFailure)?;
        let leaf_u8 = u8::try_from(leaf).map_err(|_| CryptoError::InternalFailure)?;
        let tree_index_l = *tree_indices
            .get(layer)
            .ok_or(CryptoError::InternalFailure)?;
        Ok(qhs4_leaf(
            sk_seed,
            pk_seed,
            layer_u8,
            tree_index_l,
            leaf_u8,
            &contexts,
        ))
    })?;

    let mut fors_leaves = vec![[0_u8; 32]; QHS4_FORS_LEAF_TOTAL];
    let bottom_tree = plan.bottom_tree();
    let bottom_leaf = plan.bottom_leaf();
    parallel_fill(&mut fors_leaves, threads, |index| {
        let tree = index.checked_div(QHS4_FORS_LEAVES).unwrap_or(0);
        let leaf = index.checked_rem(QHS4_FORS_LEAVES).unwrap_or(0);
        let tree_u8 = u8::try_from(tree).map_err(|_| CryptoError::InternalFailure)?;
        let leaf_u8 = u8::try_from(leaf).map_err(|_| CryptoError::InternalFailure)?;
        Ok(qhs4_fors_leaf(
            sk_seed,
            pk_seed,
            bottom_tree,
            bottom_leaf,
            tree_u8,
            leaf_u8,
            &contexts,
        ))
    })?;

    let mut hypertree = [Qhs4Tree::new([0_u8; 32], [[0_u8; 32]; QHS4_TREE_HEIGHT]); QHS4_LAYERS];
    for (layer, slot) in hypertree.iter_mut().enumerate() {
        let start = layer.checked_mul(QHS4_LEAF_COUNT).unwrap_or(0);
        let end = start.checked_add(QHS4_LEAF_COUNT).unwrap_or(0);
        let slice = hypertree_leaves
            .get(start..end)
            .ok_or(CryptoError::InternalFailure)?;
        let leaves: &[[u8; 32]; QHS4_LEAF_COUNT] =
            slice.try_into().map_err(|_| CryptoError::InternalFailure)?;
        let leaf_index = *plan
            .leaf_indices()
            .get(layer)
            .ok_or(CryptoError::InternalFailure)?;
        let (root, auth_path) = qhs4_tree_root_and_auth_from_leaves(leaves, leaf_index, &contexts)?;
        *slot = Qhs4Tree::new(root, auth_path);
    }

    let mut fors = [Qhs4ForsTree::new([0_u8; 32], [[0_u8; 32]; QHS4_FORS_HEIGHT]); QHS4_FORS_TREES];
    let fors_digest = plan.fors_digest();
    for (tree, slot) in fors.iter_mut().enumerate() {
        let start = tree.checked_mul(QHS4_FORS_LEAVES).unwrap_or(0);
        let end = start.checked_add(QHS4_FORS_LEAVES).unwrap_or(0);
        let slice = fors_leaves
            .get(start..end)
            .ok_or(CryptoError::InternalFailure)?;
        let leaves: &[[u8; 32]; QHS4_FORS_LEAVES] =
            slice.try_into().map_err(|_| CryptoError::InternalFailure)?;
        let selected = *fors_digest.get(tree).ok_or(CryptoError::InternalFailure)?;
        let (root, auth_path) = qhs4_fors_root_and_auth_from_leaves(leaves, selected, &contexts)?;
        *slot = Qhs4ForsTree::new(root, auth_path);
    }

    qhs4_sign_with_trees(private_key, message, &plan, &hypertree, &fors)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        HostEntropy, qhs_leaves_parallel, qhs2_leaves_parallel, qhs3_leaves_parallel,
        qhs4_sign_parallel,
    };

    #[test]
    fn parallel_leaves_match_sequential() {
        let seed = [7_u8; 32];
        let sequential = qwp_crypto::qhs_leaves(&seed).unwrap();
        let parallel = qhs_leaves_parallel(&seed).unwrap();
        assert_eq!(sequential, parallel);
        let sequential2 = qwp_crypto::qhs2_leaves(&seed).unwrap();
        let parallel2 = qhs2_leaves_parallel(&seed).unwrap();
        assert_eq!(sequential2, parallel2);

        let parallel3 = qhs3_leaves_parallel(&seed).unwrap();
        for index in [0_usize, 1, 42, 255, 256, 1024, 2048, 4095] {
            let leaf_index = u16::try_from(index).unwrap();
            assert_eq!(
                parallel3.get(index),
                Some(&qwp_crypto::qhs3_leaf(&seed, leaf_index).unwrap())
            );
        }
    }

    #[test]
    fn qhs4_parallel_sign_verifies() {
        let seed = [7_u8; 32];
        let (private_key, public_key) = qwp_crypto::qhs4_keygen(&seed).unwrap();
        let message = b"qWp QHS-4.1 parallel verify";
        let signature = qhs4_sign_parallel(&private_key, message).unwrap();
        assert_eq!(public_key.verify(message, &signature), Ok(()));
        assert_eq!(
            public_key.verify(b"wrong", &signature),
            Err(qwp_core::CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn qhs4_parallel_sign_matches_sequential() {
        let seed = [7_u8; 32];
        let (private_key, public_key) = qwp_crypto::qhs4_keygen(&seed).unwrap();
        let message = b"qWp QHS-4.1 parallel equivalence";
        let sequential = private_key.sign(message).unwrap();
        let parallel = qhs4_sign_parallel(&private_key, message).unwrap();
        assert_eq!(parallel, sequential);
        assert_eq!(public_key.verify(message, &parallel), Ok(()));
        assert_eq!(
            public_key.verify(b"wrong", &parallel),
            Err(qwp_core::CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn fills_requested_bytes() {
        let mut entropy = HostEntropy::open().unwrap();
        let mut output = [0_u8; 32];
        entropy.fill(&mut output).unwrap();
        assert_eq!(output.len(), 32);
        assert!(
            output.iter().any(|byte| *byte != 0),
            "entropy fill left the buffer unchanged"
        );
        assert!(std::format!("{entropy:?}").contains("HostEntropy"));
    }

    #[test]
    fn zero_length_fill_is_ok() {
        let mut entropy = HostEntropy::open().unwrap();
        let mut output = [];
        assert_eq!(entropy.fill(&mut output), Ok(()));
    }
}
