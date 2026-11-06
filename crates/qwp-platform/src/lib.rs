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
use qwp_crypto::{QHS_LEAF_COUNT, qhs_leaf};

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

#[cfg(all(test, unix))]
mod tests {
    use super::{HostEntropy, qhs_leaves_parallel};

    #[test]
    fn parallel_leaves_match_sequential() {
        let seed = [7_u8; 32];
        let sequential = qwp_crypto::qhs_leaves(&seed).unwrap();
        let parallel = qhs_leaves_parallel(&seed).unwrap();
        assert_eq!(sequential, parallel);
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
