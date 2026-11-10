//! QHS-E: embedded verifier profile for QHS-1/2/3/3.1.
//!
//! QHS-E is verifier-only. It has no key generation, signing, cache, or state
//! guard, no heap, and no `unsafe`. The public keys and signatures are exactly
//! the existing QHS-1/2/3/3.1 formats.

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
    clippy::indexing_slicing,
    reason = "fixed signature offsets are validated by exact-length parsing"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "checksum and digit arithmetic uses fixed-width wrapping operations"
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
        reason = "tests may assert and use std strings"
    )
)]

#[cfg(test)]
extern crate std;

mod verifier;

pub use verifier::{
    QHS_E_PUBLIC_KEY_BYTES, QHS_E_QHS1_SIGNATURE_BYTES, QHS_E_QHS2_SIGNATURE_BYTES,
    QHS_E_QHS3_SIGNATURE_BYTES, verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31,
};
