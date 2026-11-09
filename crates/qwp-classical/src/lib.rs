//! qWp in-tree SHA-512 and Ed25519.
//!
//! This crate exists for the QHS-6 classical hybrid. It has no external
//! dependencies and no `unsafe` code. The field and scalar code uses fixed
//! 51-bit limbs and fixed-width wrapping arithmetic.

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
#![allow(
    clippy::arithmetic_side_effects,
    reason = "field and scalar arithmetic uses fixed-width wrapping operations on 51-bit limbs"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "fixed-size limb arrays are indexed at constant positions"
)]
#![allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    reason = "limb conversions are bounded u64/u128 casts in fixed-width arithmetic"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "SHA-512 and Edwards formulas use the conventional a..h and x..y names"
)]
#![allow(
    clippy::unreadable_literal,
    reason = "field constants are grouped by 51-bit limb for auditability"
)]
#![allow(
    clippy::redundant_pub_crate,
    reason = "internal modules keep explicit pub(crate) for audit clarity"
)]
#![allow(
    clippy::needless_range_loop,
    reason = "fixed-width limb loops index parallel arrays by the same position"
)]
#![deny(clippy::alloc_instead_of_core)]
#![deny(clippy::std_instead_of_core)]
#![deny(clippy::std_instead_of_alloc)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unreachable)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::missing_inline_in_public_items)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::exhaustive_enums)]
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
        clippy::std_instead_of_alloc,
        clippy::format_push_string,
        clippy::let_underscore_must_use,
        reason = "tests may assert, index fixed arrays, use std strings, and use small numeric conversions"
    )
)]

#[cfg(test)]
extern crate std;

pub mod ed25519;
pub mod sha512;

mod edwards;
mod field;
mod scalar;

pub use ed25519::{
    ED25519_PUBLIC_KEY_BYTES, ED25519_SEED_BYTES, ED25519_SIGNATURE_BYTES, Ed25519PrivateKey,
    Ed25519PublicKey, Ed25519Signature,
};
pub use sha512::{Sha512, sha512};
