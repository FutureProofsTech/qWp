//! qWp formal verification harnesses.
//!
//! The harnesses are compiled only under Kani (`cfg(kani)`); a normal build is
//! an empty safe-Rust library.

#![no_std]
#![forbid(unsafe_code)]
#![allow(unexpected_cfgs, reason = "Kani injects cfg(kani)")]

#[cfg(kani)]
mod proofs;
