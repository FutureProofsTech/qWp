//! qWp in-tree hash types and BLAKE3 implementation.

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
#![allow(
    clippy::cargo_common_metadata,
    reason = "qWp is local-only; release metadata is finalized at packaging time"
)]
#![deny(clippy::alloc_instead_of_core)]
#![deny(clippy::std_instead_of_core)]
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
        clippy::std_instead_of_alloc,
        clippy::format_push_string,
        reason = "tests may assert, index fixed arrays, use std strings, and use small numeric conversions"
    )
)]

#[cfg(test)]
extern crate std;

pub mod blake3;

pub use blake3::{DeriveKey, Hasher, derive_key32, hash32};

use core::fmt;
use core::mem::size_of;

/// A 32-byte hash output.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash32 {
    bytes: [u8; 32],
}

impl Hash32 {
    /// Creates a hash from exactly 32 bytes.
    #[must_use]
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the exact 32-byte representation.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.bytes
    }

    /// Returns a reference to the hash bytes.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Returns `true` when every byte is zero.
    #[must_use]
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Debug for Hash32 {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Hash32(")?;
        for byte in &self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

const _: [(); 32] = [(); size_of::<Hash32>()];

#[cfg(test)]
mod tests {
    use super::Hash32;

    #[test]
    fn hash32_round_trip() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 1;
        bytes[31] = 2;
        let hash = Hash32::from_bytes(bytes);
        assert_eq!(hash.to_bytes(), bytes);
        assert_eq!(hash.as_bytes(), &bytes);
        assert!(!hash.is_zero());
    }

    #[test]
    fn hash32_debug_is_hex() {
        let hash = Hash32::from_bytes([0xab; 32]);
        let debug = std::format!("{hash:?}");
        assert!(debug.starts_with("Hash32(abab"));
    }
}
