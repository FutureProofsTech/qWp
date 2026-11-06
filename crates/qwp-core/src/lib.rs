//! qWp core types and fixed-size layouts.
//!
//! This crate is `no_std` and allocation-free. It contains the braid word and
//! polynomial representations that the rest of qWp builds on.

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
        reason = "tests may assert, index fixed arrays, and use small numeric conversions"
    )
)]

#[cfg(test)]
extern crate std;

pub mod braid;
pub mod error;
pub mod polynomial;

pub use braid::Braid;
pub use error::CryptoError;
pub use polynomial::Polynomial;

/// Number of strands in the qWp braid group.
pub const STRANDS: usize = 8;

/// Maximum number of crossings in a braid word.
pub const MAX_CROSSINGS: usize = 32;

/// Minimum valid Artin generator.
pub const MIN_GENERATOR: i8 = -7;

/// Maximum valid Artin generator.
pub const MAX_GENERATOR: i8 = 7;

/// Exact size of a braid word in bytes.
pub const BRAID_BYTES: usize = 40;

/// Number of coefficients in the public polynomial.
pub const COEFF_COUNT: usize = 129;

/// Index of degree zero in the coefficient array.
pub const DEGREE_OFFSET: usize = 64;

/// Index of degree zero as an `i32`.
pub const DEGREE_OFFSET_I32: i32 = 64;

/// Minimum polynomial degree.
pub const MIN_DEGREE: i32 = -64;

/// Maximum polynomial degree.
pub const MAX_DEGREE: i32 = 64;

/// Exact size of the public polynomial in bytes.
pub const PUBLIC_KEY_BYTES: usize = 516;

/// Exact size of a private key in bytes.
pub const PRIVATE_KEY_BYTES: usize = BRAID_BYTES;

/// Exact size of a signature in bytes.
pub const SIGNATURE_BYTES: usize = 160;
