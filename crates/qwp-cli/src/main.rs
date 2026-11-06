//! qWp command-line interface.

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
    reason = "the CLI intentionally uses std for arguments, files, and output"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the CLI is the user-facing output boundary"
)]
#![deny(clippy::alloc_instead_of_core)]
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
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::panic_in_result_fn)]
#![deny(clippy::unwrap_in_result)]
#![deny(clippy::allow_attributes_without_reason)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::mem_forget)]
#![deny(clippy::let_underscore_must_use)]
#![deny(missing_debug_implementations)]
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

use core::mem::size_of;
use std::env;
use std::process::ExitCode;

use qwp_core::{BRAID_BYTES, Braid, PUBLIC_KEY_BYTES, Polynomial, SIGNATURE_BYTES};
use qwp_crypto::{PrivateKey, PublicKey, Signature};
use qwp_hash::hash32;
use qwp_platform::HostEntropy;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("version") => {
            println!("qwp {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("hash") => {
            let input = arguments.get(2).map_or("", String::as_str);
            print_hash(input.as_bytes());
            ExitCode::SUCCESS
        }
        Some("entropy") => {
            let requested = arguments
                .get(2)
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(32);
            if requested > 4096 {
                eprintln!("entropy: maximum request is 4096 bytes");
                return ExitCode::from(2);
            }
            let mut output = vec![0_u8; requested];
            match HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut output)) {
                Ok(()) => {
                    print_hex(&output);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("entropy: {error}");
                    ExitCode::from(3)
                }
            }
        }
        Some("selftest") => {
            if selftest() {
                println!("selftest: ok");
                ExitCode::SUCCESS
            } else {
                eprintln!("selftest: failed");
                ExitCode::from(3)
            }
        }
        Some("help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!("qwp {version}", version = env!("CARGO_PKG_VERSION"));
    println!("commands:");
    println!("  version           print version");
    println!("  hash [text]       print BLAKE3 hash of text");
    println!("  entropy [n]       print n bytes from /dev/urandom (max 4096)");
    println!("  selftest          run internal layout and hash checks");
    println!("  help              show this help");
}

fn print_hash(input: &[u8]) {
    print_hex(hash32(input).as_bytes());
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}

fn selftest() -> bool {
    let braid = Braid::from_generators(&[1, -2, 7]);
    let braid_ok = braid.is_ok_and(|value| {
        let bytes = value.to_bytes();
        Braid::from_bytes(&bytes).is_ok_and(|parsed| parsed == value)
    });

    let mut polynomial = Polynomial::new();
    let polynomial_ok = polynomial.set_coefficient(0, 42).is_ok()
        && polynomial.coefficient(0) == Ok(42)
        && Polynomial::from_bytes(&polynomial.to_bytes()) == polynomial;

    let private_key_ok = braid.is_ok_and(|value| {
        let key = PrivateKey::from_braid(value);
        PrivateKey::from_bytes(&key.to_bytes()).is_ok_and(|parsed| parsed.len() == 3)
    });

    let public_key = PublicKey::from_polynomial(polynomial);
    let public_key_ok = PublicKey::from_bytes(&public_key.to_bytes()) == public_key;

    let signature = Signature::from_bytes([0_u8; SIGNATURE_BYTES]);
    let signature_ok = Signature::from_bytes(signature.to_bytes()) == signature;

    let hash_ok = std::format!("{:?}", hash32(b""))
        == "Hash32(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262)";

    braid_ok
        && polynomial_ok
        && private_key_ok
        && public_key_ok
        && signature_ok
        && hash_ok
        && size_of::<Braid>() == BRAID_BYTES
        && size_of::<Polynomial>() == PUBLIC_KEY_BYTES
        && size_of::<Signature>() == SIGNATURE_BYTES
}
