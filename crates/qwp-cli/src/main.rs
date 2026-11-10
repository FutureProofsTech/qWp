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
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

use qwp_core::{BRAID_BYTES, Braid, PUBLIC_KEY_BYTES, Polynomial, SIGNATURE_BYTES};
use qwp_crypto::{
    PrivateKey, PublicKey, QHS_LEAF_BYTES, QHS_LEAF_COUNT, QHS_PRIVATE_KEY_BYTES,
    QHS_PUBLIC_KEY_BYTES, QHS_SIGNATURE_BYTES, QHS2_LEAF_COUNT, QHS2_PRIVATE_KEY_BYTES,
    QHS2_PUBLIC_KEY_BYTES, QHS2_SIGNATURE_BYTES, QHS3_LEAF_COUNT, QHS3_PRIVATE_KEY_BYTES,
    QHS3_PUBLIC_KEY_BYTES, QHS3_SIGNATURE_BYTES, QHS3_TREE_NODES, QHS4_PRIVATE_KEY_BYTES,
    QHS4_PUBLIC_KEY_BYTES, QHS4_SIGNATURE_BYTES, QHS5_LEAF_BYTES, QHS5_LEAF_COUNT,
    QHS5_PRIVATE_KEY_BYTES, QHS5_PUBLIC_KEY_BYTES, QHS5_SIGNATURE_BYTES, QHS6_PRIVATE_KEY_BYTES,
    QHS6_PUBLIC_KEY_BYTES, QHS6_SIGNATURE_BYTES, QHS42_PRIVATE_KEY_BYTES, QHS42_PUBLIC_KEY_BYTES,
    QHS42_SIGNATURE_BYTES, Qhs2PrivateKey, Qhs2PublicKey, Qhs2Signature, Qhs3PrivateKey,
    Qhs3PublicKey, Qhs3Signature, Qhs4PrivateKey, Qhs4PublicKey, Qhs4Signature, Qhs5PrivateKey,
    Qhs5PublicKey, Qhs5Signature, Qhs6PrivateKey, Qhs6PublicKey, Qhs6Signature, Qhs42PrivateKey,
    Qhs42PublicKey, Qhs42Signature, QhsPrivateKey, QhsPublicKey, QhsSignature, Signature,
    qhs_keygen, qhs_keygen_from_leaves, qhs_leaves, qhs2_keygen, qhs2_keygen_from_leaves,
    qhs2_leaves, qhs3_auth_path_from_tree, qhs3_build_tree, qhs3_keygen_from_leaves, qhs3_leaf,
    qhs4_keygen, qhs5_keygen_from_leaves, qhs5_leaves, qhs6_keygen_from_leaves, qhs42_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};
use qwp_hash::{Hasher, derive_key32, hash32};
use qwp_platform::{
    HostEntropy, qhs_leaves_parallel, qhs2_leaves_parallel, qhs3_leaves_parallel,
    qhs4_sign_parallel, qhs5_leaves_parallel, qhs42_sign_parallel,
};

const QHS_CACHE_HEADER_BYTES: usize = 4;
const QHS_CACHE_MAC_BYTES: usize = 32;
const QHS_CACHE_FINGERPRINT_START: usize = 4;
const QHS_CACHE_FINGERPRINT_END: usize = 36;
const QHS_CACHE_LEAVES_START: usize = 36;

#[derive(Clone, Copy)]
struct CacheSpec {
    header: [u8; 4],
    fingerprint_context: &'static [u8],
    mac_context: &'static [u8],
    leaf_count: usize,
}

type LeafComputer = fn(&[u8; 32]) -> Result<Vec<[u8; 32]>, String>;

const QHS1_CACHE_SPEC: CacheSpec = CacheSpec {
    header: [1, 1, 8, 2],
    fingerprint_context: b"qWp QHS-1 cache fingerprint",
    mac_context: b"qWp QHS-1 cache mac",
    leaf_count: QHS_LEAF_COUNT,
};

const QHS2_CACHE_SPEC: CacheSpec = CacheSpec {
    header: [2, 2, 8, 2],
    fingerprint_context: b"qWp QHS-2 cache fingerprint",
    mac_context: b"qWp QHS-2 cache mac",
    leaf_count: QHS2_LEAF_COUNT,
};

const QHS3_CACHE_SPEC: CacheSpec = CacheSpec {
    header: [3, 3, 12, 2],
    fingerprint_context: b"qWp QHS-3 cache fingerprint",
    mac_context: b"qWp QHS-3 cache mac",
    leaf_count: QHS3_LEAF_COUNT,
};

const QHS31_TREE_CACHE_HEADER: [u8; 4] = [3, 3, 12, 3];
const QHS31_TREE_CACHE_FINGERPRINT_CONTEXT: &[u8] = b"qWp QHS-3.1 cache fingerprint";
const QHS31_TREE_CACHE_MAC_CONTEXT: &[u8] = b"qWp QHS-3.1 tree cache mac";
const QHS31_TREE_CACHE_LEAVES_START: usize = 36;
const QHS31_TREE_CACHE_LEAVES_END: usize =
    QHS31_TREE_CACHE_LEAVES_START + QHS3_LEAF_COUNT * QHS_LEAF_BYTES;
const QHS31_TREE_CACHE_NODES_START: usize = QHS31_TREE_CACHE_LEAVES_END;
const QHS31_TREE_CACHE_NODES_END: usize =
    QHS31_TREE_CACHE_NODES_START + QHS3_TREE_NODES * QHS_LEAF_BYTES;
const QHS31_TREE_CACHE_BYTES: usize = QHS31_TREE_CACHE_NODES_END + QHS_CACHE_MAC_BYTES;

const QHS5_CACHE_HEADER: [u8; 4] = [6, 6, 8, 2];
const QHS5_CACHE_FINGERPRINT_CONTEXT: &[u8] = b"qWp QHS-5 cache fingerprint";
const QHS5_CACHE_MAC_CONTEXT: &[u8] = b"qWp QHS-5 cache mac";
const QHS5_CACHE_LEAVES_START: usize = 36;
const QHS5_CACHE_LEAVES_END: usize = QHS5_CACHE_LEAVES_START + QHS5_LEAF_COUNT * QHS5_LEAF_BYTES;
const QHS5_CACHE_BYTES: usize = QHS5_CACHE_LEAVES_END + QHS_CACHE_MAC_BYTES;
const QHS5_STATE_GUARD_MAC_CONTEXT: &[u8] = b"qWp QHS-5 key state guard";

const QHS6_CACHE_HEADER: [u8; 4] = [7, 7, 8, 2];
const QHS6_CACHE_FINGERPRINT_CONTEXT: &[u8] = b"qWp QHS-6 cache fingerprint";
const QHS6_CACHE_MAC_CONTEXT: &[u8] = b"qWp QHS-6 cache mac";
const QHS6_CACHE_LEAVES_START: usize = QHS5_CACHE_LEAVES_START;
const QHS6_CACHE_LEAVES_END: usize = QHS5_CACHE_LEAVES_END;
const QHS6_CACHE_BYTES: usize = QHS5_CACHE_BYTES;
const QHS6_STATE_GUARD_MAC_CONTEXT: &[u8] = b"qWp QHS-6 key state guard";

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
        Some("selftest") => run_named_selftest("selftest", selftest),
        Some("qhs-selftest") => run_named_selftest("qhs-selftest", qhs_selftest),
        Some("qhs-keygen") => run_qhs_keygen(&arguments),
        Some("qhs-sign") => run_qhs_sign(&arguments),
        Some("qhs-verify") => run_qhs_verify(&arguments),
        Some("qhs2-selftest") => run_named_selftest("qhs2-selftest", qhs2_selftest),
        Some("qhs2-keygen") => run_qhs2_keygen(&arguments),
        Some("qhs2-sign") => run_qhs2_sign(&arguments),
        Some("qhs2-verify") => run_qhs2_verify(&arguments),
        Some("qhs3-selftest") => run_named_selftest("qhs3-selftest", qhs3_selftest),
        Some("qhs3-keygen") => run_qhs3_keygen(&arguments),
        Some("qhs3-sign") => run_qhs3_sign(&arguments),
        Some("qhs3-verify") => run_qhs3_verify(&arguments),
        Some("qhs31-selftest") => run_named_selftest("qhs31-selftest", qhs31_selftest),
        Some("qhs31-keygen") => run_qhs31_keygen(&arguments),
        Some("qhs31-sign") => run_qhs31_sign(&arguments),
        Some("qhs31-verify") => run_qhs31_verify(&arguments),
        Some("qhs4-selftest") => run_named_selftest("qhs4-selftest", qhs4_selftest),
        Some("qhs4-keygen") => run_qhs4_keygen(&arguments),
        Some("qhs4-sign") => run_qhs4_sign(&arguments),
        Some("qhs4-verify") => run_qhs4_verify(&arguments),
        Some("qhs41-selftest") => run_named_selftest("qhs41-selftest", qhs41_selftest),
        Some("qhs41-keygen") => run_qhs41_keygen(&arguments),
        Some("qhs41-sign") => run_qhs41_sign(&arguments),
        Some("qhs41-verify") => run_qhs41_verify(&arguments),
        Some("qhs42-selftest") => run_named_selftest("qhs42-selftest", qhs42_selftest),
        Some("qhs42-keygen") => run_qhs42_keygen(&arguments),
        Some("qhs42-sign") => run_qhs42_sign(&arguments),
        Some("qhs42-verify") => run_qhs42_verify(&arguments),
        Some("qhs5-selftest") => run_named_selftest("qhs5-selftest", qhs5_selftest),
        Some("qhs5-keygen") => run_qhs5_keygen(&arguments),
        Some("qhs5-sign") => run_qhs5_sign(&arguments),
        Some("qhs5-verify") => run_qhs5_verify(&arguments),
        Some("qhs6-selftest") => run_named_selftest("qhs6-selftest", qhs6_selftest),
        Some("qhs6-keygen") => run_qhs6_keygen(&arguments),
        Some("qhs6-sign") => run_qhs6_sign(&arguments),
        Some("qhs6-verify") => run_qhs6_verify(&arguments),
        Some("qhse-selftest") => run_named_selftest("qhse-selftest", qhse_selftest),
        Some("qhse-verify") => run_qhse_verify(&arguments),
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
    println!("  qhs-selftest      run QHS-1 keygen/sign/verify");
    println!("  qhs-keygen <pub> <key>          write QHS-1 public/private key files");
    println!("  qhs-sign <key> <message> <sig>  sign message, atomically update key counter");
    println!("  qhs-verify <pub> <message> <sig> verify QHS-1 signature");
    println!("  qhs2-selftest     run QHS-2 keygen/sign/verify");
    println!("  qhs2-keygen <pub> <key>         write QHS-2 public/private key files");
    println!("  qhs2-sign <key> <message> <sig> sign message, atomically update key counter");
    println!("  qhs2-verify <pub> <message> <sig> verify QHS-2 signature");
    println!("  qhs3-selftest     run QHS-3 keygen/sign/verify");
    println!("  qhs3-keygen <pub> <key>         write QHS-3 public/private key files");
    println!("  qhs3-sign <key> <message> <sig> sign message, atomically update key counter");
    println!("  qhs3-verify <pub> <message> <sig> verify QHS-3 signature");
    println!("  qhs31-selftest    run QHS-3.1 tree-cache keygen/sign/verify");
    println!("  qhs31-keygen <pub> <key>        write QHS-3.1 keys and tree cache");
    println!("  qhs31-sign <key> <message> <sig> fast tree-cache signing");
    println!("  qhs31-verify <pub> <message> <sig> verify QHS-3 signature");
    println!("  qhs4-selftest     run QHS-4 stateless keygen/sign/verify");
    println!("  qhs4-keygen <pub> <key>         write QHS-4 public/private key files");
    println!("  qhs4-sign <key> <message> <sig> stateless signing; key file is not modified");
    println!("  qhs4-verify <pub> <message> <sig> verify QHS-4 signature");
    println!("  qhs41-selftest    run QHS-4.1 parallel keygen/sign/verify");
    println!("  qhs41-keygen <pub> <key>        write QHS-4.1 public/private key files");
    println!("  qhs41-sign <key> <message> <sig> parallel signing; same QHS-4 signature");
    println!("  qhs41-verify <pub> <message> <sig> verify QHS-4/QHS-4.1 signature");
    println!("  qhs42-selftest    run QHS-4.2 compact keygen/sign/verify");
    println!("  qhs42-keygen <pub> <key>        write QHS-4.2 public/private key files");
    println!("  qhs42-sign <key> <message> <sig> compact parallel signing");
    println!("  qhs42-verify <pub> <message> <sig> verify QHS-4.2 signature");
    println!("  qhs5-selftest     run QHS-5 512-bit keygen/sign/verify");
    println!("  qhs5-keygen <pub> <key>         write QHS-5 keys and leaf cache");
    println!("  qhs5-sign <key> <message> <sig> stateful 512-bit signing");
    println!("  qhs5-verify <pub> <message> <sig> verify QHS-5 signature");
    println!("  qhs6-selftest     run QHS-6 hybrid keygen/sign/verify");
    println!("  qhs6-keygen <pub> <key>         write QHS-6 hybrid keys and leaf cache");
    println!("  qhs6-sign <key> <message> <sig> QHS-5 + Ed25519 hybrid signing");
    println!("  qhs6-verify <pub> <message> <sig> verify both hybrid signatures");
    println!("  qhse-selftest     run QHS-E QHS-1/2/3 verifier profile");
    println!("  qhse-verify <v> <pub> <message> <sig> embedded verifier (v=1,2,3,31)");
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

fn run_qhs_keygen(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp qhs-keygen <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("qhs-keygen: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seed = [0_u8; 32];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seed)) {
        eprintln!("qhs-keygen: {error}");
        return ExitCode::from(3);
    }
    let leaves = match compute_leaves_for_cli(&seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let Some(leaves) = leaf_array::<QHS_LEAF_COUNT>(&leaves) else {
        eprintln!("qhs-keygen: invalid leaf count");
        return ExitCode::from(3);
    };
    match qhs_keygen_from_leaves(&seed, leaves) {
        Ok((private_key, public_key)) => {
            let key_bytes = private_key.to_bytes();
            if let Err(error) = write_atomic(private_path, &key_bytes, true) {
                eprintln!("qhs-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_qhs_cache(private_path, &seed, leaves, &QHS1_CACHE_SPEC) {
                eprintln!("qhs-keygen: warning: cache not written: {error}");
            }
            if let Err(error) = write_state_guard(private_path, &seed, &key_bytes, 0) {
                eprintln!("qhs-keygen: warning: state guard not written: {error}");
            }
            println!("qhs-keygen: wrote {public_path}, {private_path}, and cache");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs-keygen: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs_sign(arguments: &[String]) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs-sign <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let key_vec = match read_exact_file(private_path, QHS_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("qhs-sign: invalid private key length");
        return ExitCode::from(3);
    };
    let mut private_key = match QhsPrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if private_key.is_exhausted() {
        eprintln!("qhs-sign: key exhausted");
        return ExitCode::from(3);
    }
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs-sign: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let seed = *private_key.seed();
    let state_key = private_key.to_bytes();
    if let Err(error) = check_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs-sign: {error}");
        return ExitCode::from(3);
    }
    let leaves = match load_or_compute_leaves(private_path, &seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Some(leaves) = leaf_array::<QHS_LEAF_COUNT>(&leaves) else {
        eprintln!("qhs-sign: invalid leaf count");
        return ExitCode::from(3);
    };
    let signature = match private_key.sign_with_leaves(&message, leaves) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
        eprintln!("qhs-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = update_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("qhs-sign: {error}");
        return ExitCode::from(3);
    }
    println!("qhs-sign: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs_verify(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs-verify <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhs-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match QhsPublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(signature_bytes) = <[u8; QHS_SIGNATURE_BYTES]>::try_from(signature_vec.as_slice())
    else {
        eprintln!("qhs-verify: invalid signature length");
        return ExitCode::from(3);
    };
    let signature = QhsSignature::from_bytes(signature_bytes);
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("qhs-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhs2_keygen(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp qhs2-keygen <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("qhs2-keygen: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs2-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seed = [0_u8; 32];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seed)) {
        eprintln!("qhs2-keygen: {error}");
        return ExitCode::from(3);
    }
    let leaves = match compute_leaves_for_cli_v2(&seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs2-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let Some(leaves) = leaf_array::<QHS2_LEAF_COUNT>(&leaves) else {
        eprintln!("qhs2-keygen: invalid leaf count");
        return ExitCode::from(3);
    };
    match qhs2_keygen_from_leaves(&seed, leaves) {
        Ok((private_key, public_key)) => {
            let key_bytes = private_key.to_bytes();
            if let Err(error) = write_atomic(private_path, &key_bytes, true) {
                eprintln!("qhs2-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs2-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_qhs_cache(private_path, &seed, leaves, &QHS2_CACHE_SPEC) {
                eprintln!("qhs2-keygen: warning: cache not written: {error}");
            }
            if let Err(error) = write_state_guard(private_path, &seed, &key_bytes, 0) {
                eprintln!("qhs2-keygen: warning: state guard not written: {error}");
            }
            println!("qhs2-keygen: wrote {public_path}, {private_path}, and cache");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs2-keygen: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs2_sign(arguments: &[String]) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs2-sign <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs2-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let key_vec = match read_exact_file(private_path, QHS2_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs2-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS2_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("qhs2-sign: invalid private key length");
        return ExitCode::from(3);
    };
    let mut private_key = match Qhs2PrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs2-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if private_key.is_exhausted() {
        eprintln!("qhs2-sign: key exhausted");
        return ExitCode::from(3);
    }
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs2-sign: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let seed = *private_key.seed();
    let state_key = private_key.to_bytes();
    if let Err(error) = check_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs2-sign: {error}");
        return ExitCode::from(3);
    }
    let leaves = match load_or_compute_leaves_v2(private_path, &seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs2-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Some(leaves) = leaf_array::<QHS2_LEAF_COUNT>(&leaves) else {
        eprintln!("qhs2-sign: invalid leaf count");
        return ExitCode::from(3);
    };
    let signature = match private_key.sign_with_leaves(&message, leaves) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs2-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
        eprintln!("qhs2-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = update_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs2-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("qhs2-sign: {error}");
        return ExitCode::from(3);
    }
    println!("qhs2-sign: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs2_verify(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs2-verify <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS2_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs2-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS2_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhs2-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match Qhs2PublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs2-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS2_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs2-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(signature_bytes) = <[u8; QHS2_SIGNATURE_BYTES]>::try_from(signature_vec.as_slice())
    else {
        eprintln!("qhs2-verify: invalid signature length");
        return ExitCode::from(3);
    };
    let signature = Qhs2Signature::from_bytes(signature_bytes);
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs2-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("qhs2-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs2-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhs3_keygen(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp qhs3-keygen <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("qhs3-keygen: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs3-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seed = [0_u8; 32];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seed)) {
        eprintln!("qhs3-keygen: {error}");
        return ExitCode::from(3);
    }
    let leaves = match compute_leaves_for_cli_v3(&seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs3-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    match qhs3_keygen_from_leaves(&seed, &leaves) {
        Ok((private_key, public_key)) => {
            let key_bytes = private_key.to_bytes();
            if let Err(error) = write_atomic(private_path, &key_bytes, true) {
                eprintln!("qhs3-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs3-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_qhs_cache(private_path, &seed, &leaves, &QHS3_CACHE_SPEC) {
                eprintln!("qhs3-keygen: warning: cache not written: {error}");
            }
            if let Err(error) = write_state_guard(private_path, &seed, &key_bytes, 0) {
                eprintln!("qhs3-keygen: warning: state guard not written: {error}");
            }
            println!("qhs3-keygen: wrote {public_path}, {private_path}, and cache");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs3-keygen: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs3_sign(arguments: &[String]) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs3-sign <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs3-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let key_vec = match read_exact_file(private_path, QHS3_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs3-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS3_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("qhs3-sign: invalid private key length");
        return ExitCode::from(3);
    };
    let mut private_key = match Qhs3PrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs3-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if private_key.is_exhausted() {
        eprintln!("qhs3-sign: key exhausted");
        return ExitCode::from(3);
    }
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs3-sign: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let seed = *private_key.seed();
    let state_key = private_key.to_bytes();
    if let Err(error) = check_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs3-sign: {error}");
        return ExitCode::from(3);
    }
    let leaves = match load_or_compute_leaves_v3(private_path, &seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs3-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match private_key.sign_with_leaves(&message, &leaves) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs3-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
        eprintln!("qhs3-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = update_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs3-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("qhs3-sign: {error}");
        return ExitCode::from(3);
    }
    println!("qhs3-sign: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs3_verify(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs3-verify <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS3_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs3-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS3_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhs3-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match Qhs3PublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs3-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS3_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs3-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(signature_bytes) = <[u8; QHS3_SIGNATURE_BYTES]>::try_from(signature_vec.as_slice())
    else {
        eprintln!("qhs3-verify: invalid signature length");
        return ExitCode::from(3);
    };
    let signature = Qhs3Signature::from_bytes(signature_bytes);
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs3-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("qhs3-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs3-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhs31_keygen(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp qhs31-keygen <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("qhs31-keygen: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs31-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seed = [0_u8; 32];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seed)) {
        eprintln!("qhs31-keygen: {error}");
        return ExitCode::from(3);
    }
    let tree = match compute_tree_for_cli_v31(&seed) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("qhs31-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    match qhs3_keygen_from_leaves(&seed, &tree.leaves) {
        Ok((private_key, public_key)) => {
            let key_bytes = private_key.to_bytes();
            if let Err(error) = write_atomic(private_path, &key_bytes, true) {
                eprintln!("qhs31-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs31-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_qhs31_cache(private_path, &seed, &tree) {
                eprintln!("qhs31-keygen: warning: tree cache not written: {error}");
            }
            if let Err(error) = write_state_guard(private_path, &seed, &key_bytes, 0) {
                eprintln!("qhs31-keygen: warning: state guard not written: {error}");
            }
            println!("qhs31-keygen: wrote {public_path}, {private_path}, and tree cache");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs31-keygen: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs31_sign(arguments: &[String]) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs31-sign <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs31-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let key_vec = match read_exact_file(private_path, QHS3_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs31-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS3_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("qhs31-sign: invalid private key length");
        return ExitCode::from(3);
    };
    let mut private_key = match Qhs3PrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs31-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if private_key.is_exhausted() {
        eprintln!("qhs31-sign: key exhausted");
        return ExitCode::from(3);
    }
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs31-sign: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let seed = *private_key.seed();
    let state_key = private_key.to_bytes();
    if let Err(error) = check_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs31-sign: {error}");
        return ExitCode::from(3);
    }
    let tree = match load_or_compute_tree_v31(private_path, &seed) {
        Ok(tree) => tree,
        Err(error) => {
            eprintln!("qhs31-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let auth_path =
        match qhs3_auth_path_from_tree(&tree.leaves, &tree.nodes, private_key.next_leaf()) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("qhs31-sign: {error}");
                return ExitCode::from(3);
            }
        };
    let signature = match private_key.sign_with_auth_path(&message, &auth_path) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs31-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
        eprintln!("qhs31-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = update_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs31-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("qhs31-sign: {error}");
        return ExitCode::from(3);
    }
    println!("qhs31-sign: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs31_verify(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs31-verify <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS3_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs31-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS3_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhs31-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match Qhs3PublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs31-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS3_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs31-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(signature_bytes) = <[u8; QHS3_SIGNATURE_BYTES]>::try_from(signature_vec.as_slice())
    else {
        eprintln!("qhs31-verify: invalid signature length");
        return ExitCode::from(3);
    };
    let signature = Qhs3Signature::from_bytes(signature_bytes);
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs31-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("qhs31-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs31-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhs4_keygen(arguments: &[String]) -> ExitCode {
    run_qhs4_keygen_named(arguments, "qhs4-keygen")
}

fn run_qhs41_keygen(arguments: &[String]) -> ExitCode {
    run_qhs4_keygen_named(arguments, "qhs41-keygen")
}

fn run_qhs4_keygen_named(arguments: &[String], name: &str) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp {name} <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("{name}: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seed = [0_u8; 32];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seed)) {
        eprintln!("{name}: {error}");
        return ExitCode::from(3);
    }
    match qhs4_keygen(&seed) {
        Ok((private_key, public_key)) => {
            if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
                eprintln!("{name}: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("{name}: {error}");
                return ExitCode::from(3);
            }
            println!("{name}: wrote {public_path} and {private_path}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{name}: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs4_sign(arguments: &[String]) -> ExitCode {
    run_qhs4_sign_named(arguments, "qhs4-sign", false)
}

fn run_qhs41_sign(arguments: &[String]) -> ExitCode {
    run_qhs4_sign_named(arguments, "qhs41-sign", true)
}

fn run_qhs4_sign_named(arguments: &[String], name: &str, parallel: bool) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp {name} <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let key_vec = match read_exact_file(private_path, QHS4_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS4_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("{name}: invalid private key length");
        return ExitCode::from(3);
    };
    let private_key = match Qhs4PrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{name}: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = if parallel {
        qhs4_sign_parallel(&private_key, &message)
    } else {
        private_key.sign(&message)
    };
    let signature = match signature {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("{name}: {error}");
        return ExitCode::from(3);
    }
    println!("{name}: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs4_verify(arguments: &[String]) -> ExitCode {
    run_qhs4_verify_named(arguments, "qhs4-verify")
}

fn run_qhs41_verify(arguments: &[String]) -> ExitCode {
    run_qhs4_verify_named(arguments, "qhs41-verify")
}

fn run_qhs4_verify_named(arguments: &[String], name: &str) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp {name} <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS4_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS4_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("{name}: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match Qhs4PublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS4_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match Qhs4Signature::from_slice(&signature_vec) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("{name}: {error}");
            return ExitCode::from(3);
        }
    };
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{name}: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("{name}: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{name}: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhs42_keygen(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp qhs42-keygen <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("qhs42-keygen: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs42-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seed = [0_u8; 32];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seed)) {
        eprintln!("qhs42-keygen: {error}");
        return ExitCode::from(3);
    }
    match qhs42_keygen(&seed) {
        Ok((private_key, public_key)) => {
            if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
                eprintln!("qhs42-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs42-keygen: {error}");
                return ExitCode::from(3);
            }
            println!("qhs42-keygen: wrote {public_path} and {private_path}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs42-keygen: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs42_sign(arguments: &[String]) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs42-sign <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let key_vec = match read_exact_file(private_path, QHS42_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs42-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS42_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("qhs42-sign: invalid private key length");
        return ExitCode::from(3);
    };
    let private_key = match Qhs42PrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs42-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs42-sign: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match qhs42_sign_parallel(&private_key, &message) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs42-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("qhs42-sign: {error}");
        return ExitCode::from(3);
    }
    println!("qhs42-sign: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs42_verify(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs42-verify <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS42_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs42-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS42_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhs42-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match Qhs42PublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs42-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS42_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs42-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match Qhs42Signature::from_slice(&signature_vec) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs42-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs42-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("qhs42-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs42-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhs5_keygen(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp qhs5-keygen <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("qhs5-keygen: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs5-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seed = [0_u8; 64];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seed)) {
        eprintln!("qhs5-keygen: {error}");
        return ExitCode::from(3);
    }
    let leaves = match compute_leaves_for_cli_v5(&seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs5-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    match qhs5_keygen_from_leaves(&seed, &leaves) {
        Ok((private_key, public_key)) => {
            let key_bytes = private_key.to_bytes();
            if let Err(error) = write_atomic(private_path, &key_bytes, true) {
                eprintln!("qhs5-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs5-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_qhs5_cache(private_path, &seed, &leaves) {
                eprintln!("qhs5-keygen: warning: cache not written: {error}");
            }
            if let Err(error) = write_qhs5_state_guard(private_path, &seed, &key_bytes, 0) {
                eprintln!("qhs5-keygen: warning: state guard not written: {error}");
            }
            println!("qhs5-keygen: wrote {public_path}, {private_path}, and cache");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs5-keygen: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs5_sign(arguments: &[String]) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs5-sign <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs5-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let key_vec = match read_exact_file(private_path, QHS5_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs5-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS5_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("qhs5-sign: invalid private key length");
        return ExitCode::from(3);
    };
    let mut private_key = match Qhs5PrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs5-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if private_key.is_exhausted() {
        eprintln!("qhs5-sign: key exhausted");
        return ExitCode::from(3);
    }
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs5-sign: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let seed = *private_key.seed();
    let state_key = private_key.to_bytes();
    if let Err(error) =
        check_qhs5_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs5-sign: {error}");
        return ExitCode::from(3);
    }
    let leaves = match load_or_compute_leaves_v5(private_path, &seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs5-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match private_key.sign_with_leaves(&message, &leaves) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs5-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
        eprintln!("qhs5-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) =
        update_qhs5_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs5-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("qhs5-sign: {error}");
        return ExitCode::from(3);
    }
    println!("qhs5-sign: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs5_verify(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs5-verify <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS5_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs5-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS5_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhs5-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match Qhs5PublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs5-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS5_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs5-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match Qhs5Signature::from_slice(&signature_vec) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs5-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs5-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("qhs5-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs5-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhs6_keygen(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(private_path)) = (arguments.get(2), arguments.get(3)) else {
        eprintln!("usage: qwp qhs6-keygen <public-key> <private-key>");
        return ExitCode::from(2);
    };
    if Path::new(private_path).exists() {
        eprintln!("qhs6-keygen: refusing to overwrite existing {private_path}");
        return ExitCode::from(2);
    }
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs6-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    let mut seeds = [0_u8; 96];
    if let Err(error) = HostEntropy::open().and_then(|mut entropy| entropy.fill(&mut seeds)) {
        eprintln!("qhs6-keygen: {error}");
        return ExitCode::from(3);
    }
    let mut qhs5_seed = [0_u8; 64];
    qhs5_seed.copy_from_slice(&seeds[..64]);
    let mut ed25519_seed = [0_u8; 32];
    ed25519_seed.copy_from_slice(&seeds[64..]);
    let leaves = match compute_leaves_for_cli_v5(&qhs5_seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs6-keygen: {error}");
            return ExitCode::from(3);
        }
    };
    match qhs6_keygen_from_leaves(&qhs5_seed, &ed25519_seed, &leaves) {
        Ok((private_key, public_key)) => {
            let key_bytes = private_key.to_bytes();
            if let Err(error) = write_atomic(private_path, &key_bytes, true) {
                eprintln!("qhs6-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs6-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_qhs6_cache(private_path, &qhs5_seed, &leaves) {
                eprintln!("qhs6-keygen: warning: cache not written: {error}");
            }
            if let Err(error) = write_qhs6_state_guard(private_path, &qhs5_seed, &key_bytes, 0) {
                eprintln!("qhs6-keygen: warning: state guard not written: {error}");
            }
            println!("qhs6-keygen: wrote {public_path}, {private_path}, and cache");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs6-keygen: {error}");
            ExitCode::from(3)
        }
    }
}

fn run_qhs6_sign(arguments: &[String]) -> ExitCode {
    let (Some(private_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs6-sign <private-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let _lock_file = match lock_key(private_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("qhs6-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let key_vec = match read_exact_file(private_path, QHS6_PRIVATE_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs6-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(key_bytes) = <[u8; QHS6_PRIVATE_KEY_BYTES]>::try_from(key_vec.as_slice()) else {
        eprintln!("qhs6-sign: invalid private key length");
        return ExitCode::from(3);
    };
    let mut private_key = match Qhs6PrivateKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs6-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if private_key.is_exhausted() {
        eprintln!("qhs6-sign: key exhausted");
        return ExitCode::from(3);
    }
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs6-sign: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let seed = *private_key.qhs5_seed();
    let state_key = private_key.to_bytes();
    if let Err(error) =
        check_qhs6_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs6-sign: {error}");
        return ExitCode::from(3);
    }
    let leaves = match load_or_compute_leaves_v6(private_path, &seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs6-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match private_key.sign_with_leaves(&message, &leaves) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs6-sign: {error}");
            return ExitCode::from(3);
        }
    };
    if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
        eprintln!("qhs6-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) =
        update_qhs6_state_guard(private_path, &seed, &state_key, private_key.next_leaf())
    {
        eprintln!("qhs6-sign: {error}");
        return ExitCode::from(3);
    }
    if let Err(error) = write_atomic(signature_path, &signature.to_bytes(), false) {
        eprintln!("qhs6-sign: {error}");
        return ExitCode::from(3);
    }
    println!("qhs6-sign: wrote {signature_path}");
    ExitCode::SUCCESS
}

fn run_qhs6_verify(arguments: &[String]) -> ExitCode {
    let (Some(public_path), Some(message_path), Some(signature_path)) =
        (arguments.get(2), arguments.get(3), arguments.get(4))
    else {
        eprintln!("usage: qwp qhs6-verify <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let public_vec = match read_exact_file(public_path, QHS6_PUBLIC_KEY_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs6-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; QHS6_PUBLIC_KEY_BYTES]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhs6-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let public_key = match Qhs6PublicKey::from_bytes(&public_bytes) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("qhs6-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature_vec = match read_exact_file(signature_path, QHS6_SIGNATURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs6-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match Qhs6Signature::from_slice(&signature_vec) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("qhs6-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhs6-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    match public_key.verify(&message, &signature) {
        Ok(()) => {
            println!("qhs6-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhs6-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_qhse_verify(arguments: &[String]) -> ExitCode {
    let (Some(version), Some(public_path), Some(message_path), Some(signature_path)) = (
        arguments.get(2),
        arguments.get(3),
        arguments.get(4),
        arguments.get(5),
    ) else {
        eprintln!("usage: qwp qhse-verify <1|2|3|31> <public-key> <message> <signature>");
        return ExitCode::from(2);
    };
    let signature_bytes = match version.as_str() {
        "1" => 2_408,
        "2" => 1_704,
        "3" | "31" => 1_832,
        _ => {
            eprintln!("qhse-verify: version must be 1, 2, 3, or 31");
            return ExitCode::from(2);
        }
    };
    let public_vec = match read_exact_file(public_path, 64) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhse-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let Ok(public_bytes) = <[u8; 64]>::try_from(public_vec.as_slice()) else {
        eprintln!("qhse-verify: invalid public key length");
        return ExitCode::from(3);
    };
    let signature_vec = match read_exact_file(signature_path, signature_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhse-verify: {error}");
            return ExitCode::from(3);
        }
    };
    let message = match fs::read(message_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("qhse-verify: {message_path}: {error}");
            return ExitCode::from(3);
        }
    };
    let result = match version.as_str() {
        "1" => <[u8; 2_408]>::try_from(signature_vec.as_slice())
            .map_err(|_| "invalid QHS-1 signature length".to_string())
            .and_then(|signature| {
                verify_qhs1(&public_bytes, &message, &signature).map_err(|error| error.to_string())
            }),
        "2" => <[u8; 1_704]>::try_from(signature_vec.as_slice())
            .map_err(|_| "invalid QHS-2 signature length".to_string())
            .and_then(|signature| {
                verify_qhs2(&public_bytes, &message, &signature).map_err(|error| error.to_string())
            }),
        "3" => <[u8; 1_832]>::try_from(signature_vec.as_slice())
            .map_err(|_| "invalid QHS-3 signature length".to_string())
            .and_then(|signature| {
                verify_qhs3(&public_bytes, &message, &signature).map_err(|error| error.to_string())
            }),
        "31" => <[u8; 1_832]>::try_from(signature_vec.as_slice())
            .map_err(|_| "invalid QHS-3.1 signature length".to_string())
            .and_then(|signature| {
                verify_qhs31(&public_bytes, &message, &signature).map_err(|error| error.to_string())
            }),
        _ => Err("invalid version".to_string()),
    };
    match result {
        Ok(()) => {
            println!("qhse-verify: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qhse-verify: {error}");
            ExitCode::from(1)
        }
    }
}

fn qhse_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok(leaves1) = qhs_leaves_parallel(&seed) else {
        return false;
    };
    let Ok((mut private1, public1)) = qhs_keygen_from_leaves(&seed, &leaves1) else {
        return false;
    };
    let Ok(signature1) = private1.sign(b"qhse-selftest") else {
        return false;
    };
    let Ok(leaves2) = qhs2_leaves_parallel(&seed) else {
        return false;
    };
    let Ok((mut private2, public2)) = qhs2_keygen_from_leaves(&seed, &leaves2) else {
        return false;
    };
    let Ok(signature2) = private2.sign(b"qhse-selftest") else {
        return false;
    };
    let Ok(leaves3) = qhs3_leaves_parallel(&seed) else {
        return false;
    };
    let Ok((mut private3, public3)) = qhs3_keygen_from_leaves(&seed, &leaves3) else {
        return false;
    };
    let Ok(signature3) = private3.sign(b"qhse-selftest") else {
        return false;
    };
    all_true(&[
        verify_qhs1(
            &public1.to_bytes(),
            b"qhse-selftest",
            &signature1.to_bytes(),
        )
        .is_ok(),
        verify_qhs2(
            &public2.to_bytes(),
            b"qhse-selftest",
            &signature2.to_bytes(),
        )
        .is_ok(),
        verify_qhs3(
            &public3.to_bytes(),
            b"qhse-selftest",
            &signature3.to_bytes(),
        )
        .is_ok(),
        verify_qhs31(
            &public3.to_bytes(),
            b"qhse-selftest",
            &signature3.to_bytes(),
        )
        .is_ok(),
        verify_qhs1(&public1.to_bytes(), b"wrong", &signature1.to_bytes()).is_err(),
    ])
}

fn lock_key(path: &str) -> Result<fs::File, String> {
    let lock_path = format!("{path}.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| format!("{lock_path}: {error}"))?;
    file.try_lock()
        .map_err(|_| format!("{path}: locked by another process"))?;
    Ok(file)
}

fn cache_path(private_path: &str) -> String {
    format!("{private_path}.cache")
}

const STATE_GUARD_BYTES: usize = 38;
const STATE_GUARD_MAC_CONTEXT: &[u8] = b"qWp key state guard";

fn state_path(private_path: &str) -> String {
    format!("{private_path}.state")
}

fn state_guard_mac(seed: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(STATE_GUARD_MAC_CONTEXT, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn write_state_guard(
    private_path: &str,
    seed: &[u8; 32],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    let mut body = [0_u8; 6];
    if let (Some(slot), Some(header)) = (body.get_mut(..4), key_bytes.get(..4)) {
        slot.copy_from_slice(header);
        if let Some(byte) = slot.get_mut(3) {
            *byte = 0;
        }
    } else {
        return Err("state guard layout".to_string());
    }
    if let Some(slot) = body.get_mut(4..6) {
        slot.copy_from_slice(&counter.to_le_bytes());
    }
    let mac = state_guard_mac(seed, &body);
    let mut bytes = [0_u8; STATE_GUARD_BYTES];
    let (header, tag) = bytes.split_at_mut(6);
    header.copy_from_slice(&body);
    tag.copy_from_slice(&mac);
    write_atomic(&state_path(private_path), &bytes, true)
}

fn read_state_guard(private_path: &str, seed: &[u8; 32]) -> Result<Option<[u8; 6]>, String> {
    let path = state_path(private_path);
    if !Path::new(&path).exists() {
        return Ok(None);
    }
    let bytes = read_exact_file(&path, STATE_GUARD_BYTES)?;
    let body = bytes
        .get(..6)
        .ok_or_else(|| "state guard layout".to_string())?;
    let expected = state_guard_mac(seed, body);
    if bytes.get(6..) != Some(expected.as_slice()) {
        return Err("state guard is corrupt or belongs to a different key".to_string());
    }
    let mut output = [0_u8; 6];
    output.copy_from_slice(body);
    Ok(Some(output))
}

fn check_state_guard(
    private_path: &str,
    seed: &[u8; 32],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    let guard = match read_state_guard(private_path, seed) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            if counter > 0 {
                return Err(
                    "state guard is missing for an advanced key; restore the guard file"
                        .to_string(),
                );
            }
            return write_state_guard(private_path, seed, key_bytes, counter);
        }
        Err(error) => return Err(error),
    };
    let Some(header) = key_bytes.get(..4) else {
        return Err("state guard key layout".to_string());
    };
    if guard.get(..4) != Some(header) {
        return Err("key state guard belongs to a different key".to_string());
    }
    let guard_counter = guard
        .get(4..6)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(0, u16::from_le_bytes);
    if guard_counter > counter {
        return Err(format!(
            "key state rollback detected: guard {guard_counter} > key {counter}"
        ));
    }
    if guard_counter < counter {
        write_state_guard(private_path, seed, key_bytes, counter)?;
    }
    Ok(())
}

fn update_state_guard(
    private_path: &str,
    seed: &[u8; 32],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    write_state_guard(private_path, seed, key_bytes, counter)
}

fn cache_fingerprint(seed: &[u8; 32], spec: &CacheSpec) -> [u8; 32] {
    derive_key32(spec.fingerprint_context, seed).to_bytes()
}

fn cache_mac(seed: &[u8; 32], context: &[u8], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(context, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn leaf_array<const N: usize>(leaves: &[[u8; 32]]) -> Option<&[[u8; 32]; N]> {
    <&[[u8; 32]; N]>::try_from(leaves).ok()
}

fn cache_leaves_end(spec: &CacheSpec) -> Option<usize> {
    spec.leaf_count
        .checked_mul(QHS_LEAF_BYTES)?
        .checked_add(QHS_CACHE_LEAVES_START)
}

fn cache_total(spec: &CacheSpec) -> Option<usize> {
    cache_leaves_end(spec)?.checked_add(QHS_CACHE_MAC_BYTES)
}

fn compute_leaves_for_cli(seed: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    qhs_leaves_parallel(seed)
        .map(|leaves| leaves.to_vec())
        .map_or_else(
            |_| {
                qhs_leaves(seed)
                    .map(|leaves| leaves.to_vec())
                    .map_err(|error| error.to_string())
            },
            Ok,
        )
}

fn compute_leaves_for_cli_v2(seed: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    qhs2_leaves_parallel(seed)
        .map(|leaves| leaves.to_vec())
        .map_or_else(
            |_| {
                qhs2_leaves(seed)
                    .map(|leaves| leaves.to_vec())
                    .map_err(|error| error.to_string())
            },
            Ok,
        )
}

fn compute_leaves_for_cli_v3(seed: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    qhs3_leaves_parallel(seed).map_or_else(
        |_| {
            let mut leaves = Vec::with_capacity(QHS3_LEAF_COUNT);
            for index in 0..QHS3_LEAF_COUNT {
                let leaf_index =
                    u16::try_from(index).map_err(|_| "invalid leaf index".to_string())?;
                leaves.push(qhs3_leaf(seed, leaf_index).map_err(|error| error.to_string())?);
            }
            Ok(leaves)
        },
        Ok,
    )
}

fn load_or_compute_leaves(private_path: &str, seed: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    load_or_compute_leaves_with(private_path, seed, &QHS1_CACHE_SPEC, compute_leaves_for_cli)
}

fn load_or_compute_leaves_v2(private_path: &str, seed: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    load_or_compute_leaves_with(
        private_path,
        seed,
        &QHS2_CACHE_SPEC,
        compute_leaves_for_cli_v2,
    )
}

fn load_or_compute_leaves_v3(private_path: &str, seed: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    load_or_compute_leaves_with(
        private_path,
        seed,
        &QHS3_CACHE_SPEC,
        compute_leaves_for_cli_v3,
    )
}

fn load_or_compute_leaves_with(
    private_path: &str,
    seed: &[u8; 32],
    spec: &CacheSpec,
    compute: LeafComputer,
) -> Result<Vec<[u8; 32]>, String> {
    let path = cache_path(private_path);
    if let Some(leaves) = read_qhs_cache(&path, seed, spec) {
        return Ok(leaves);
    }
    let leaves = compute(seed)?;
    if let Err(error) = write_qhs_cache(private_path, seed, &leaves, spec) {
        eprintln!("qhs-sign: warning: cache not written: {error}");
    }
    Ok(leaves)
}

fn write_qhs_cache(
    private_path: &str,
    seed: &[u8; 32],
    leaves: &[[u8; 32]],
    spec: &CacheSpec,
) -> Result<(), String> {
    if leaves.len() != spec.leaf_count {
        return Err("cache leaf count".to_string());
    }
    let leaves_end = cache_leaves_end(spec).ok_or_else(|| "cache layout".to_string())?;
    let total = cache_total(spec).ok_or_else(|| "cache layout".to_string())?;
    let mut bytes = vec![0_u8; total];
    if let Some(slot) = bytes.get_mut(0..QHS_CACHE_HEADER_BYTES) {
        slot.copy_from_slice(&spec.header);
    }
    if let Some(slot) = bytes.get_mut(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END) {
        slot.copy_from_slice(&cache_fingerprint(seed, spec));
    }
    if let Some(slot) = bytes.get_mut(QHS_CACHE_LEAVES_START..leaves_end) {
        for (destination, source) in slot
            .as_chunks_mut::<QHS_LEAF_BYTES>()
            .0
            .iter_mut()
            .zip(leaves.iter())
        {
            destination.copy_from_slice(source);
        }
    }
    let body = bytes
        .get(..leaves_end)
        .ok_or_else(|| "cache layout".to_string())?;
    let mac = cache_mac(seed, spec.mac_context, body);
    if let Some(slot) = bytes.get_mut(leaves_end..total) {
        slot.copy_from_slice(&mac);
    }
    write_atomic(&cache_path(private_path), &bytes, true)
}

fn read_qhs_cache(path: &str, seed: &[u8; 32], spec: &CacheSpec) -> Option<Vec<[u8; 32]>> {
    let total = cache_total(spec)?;
    let file = fs::File::open(path).ok()?;
    let limit = u64::try_from(total).ok()?.saturating_add(1);
    let mut bytes = Vec::with_capacity(total.saturating_add(1));
    let read = file.take(limit).read_to_end(&mut bytes).ok()?;
    if read != total {
        return None;
    }
    if bytes.get(0..QHS_CACHE_HEADER_BYTES) != Some(spec.header.as_slice()) {
        return None;
    }
    let expected_fingerprint = cache_fingerprint(seed, spec);
    if bytes.get(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END)?
        != expected_fingerprint.as_slice()
    {
        return None;
    }
    let leaves_end = cache_leaves_end(spec)?;
    let body = bytes.get(..leaves_end)?;
    let expected_mac = cache_mac(seed, spec.mac_context, body);
    if bytes.get(leaves_end..total)? != expected_mac.as_slice() {
        return None;
    }

    let mut leaves = Vec::with_capacity(spec.leaf_count);
    for chunk in bytes
        .get(QHS_CACHE_LEAVES_START..leaves_end)?
        .as_chunks::<QHS_LEAF_BYTES>()
        .0
    {
        leaves.push(*chunk);
    }
    Some(leaves)
}

fn qhs5_cache_fingerprint(seed: &[u8; 64]) -> [u8; 32] {
    derive_key32(QHS5_CACHE_FINGERPRINT_CONTEXT, seed).to_bytes()
}

fn qhs5_cache_mac(seed: &[u8; 64], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(QHS5_CACHE_MAC_CONTEXT, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn compute_leaves_for_cli_v5(seed: &[u8; 64]) -> Result<[[u8; 64]; QHS5_LEAF_COUNT], String> {
    qhs5_leaves_parallel(seed)
        .map_or_else(|_| qhs5_leaves(seed).map_err(|error| error.to_string()), Ok)
}

fn load_or_compute_leaves_v5(
    private_path: &str,
    seed: &[u8; 64],
) -> Result<[[u8; 64]; QHS5_LEAF_COUNT], String> {
    let path = cache_path(private_path);
    if let Some(leaves) = read_qhs5_cache(&path, seed) {
        return Ok(leaves);
    }
    let leaves = compute_leaves_for_cli_v5(seed)?;
    if let Err(error) = write_qhs5_cache(private_path, seed, &leaves) {
        eprintln!("qhs5-sign: warning: cache not written: {error}");
    }
    Ok(leaves)
}

fn write_qhs5_cache(
    private_path: &str,
    seed: &[u8; 64],
    leaves: &[[u8; 64]; QHS5_LEAF_COUNT],
) -> Result<(), String> {
    let mut bytes = vec![0_u8; QHS5_CACHE_BYTES];
    if let Some(slot) = bytes.get_mut(0..QHS_CACHE_HEADER_BYTES) {
        slot.copy_from_slice(&QHS5_CACHE_HEADER);
    }
    if let Some(slot) = bytes.get_mut(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END) {
        slot.copy_from_slice(&qhs5_cache_fingerprint(seed));
    }
    if let Some(slot) = bytes.get_mut(QHS5_CACHE_LEAVES_START..QHS5_CACHE_LEAVES_END) {
        for (destination, source) in slot
            .as_chunks_mut::<QHS5_LEAF_BYTES>()
            .0
            .iter_mut()
            .zip(leaves.iter())
        {
            destination.copy_from_slice(source);
        }
    }
    let body = bytes
        .get(..QHS5_CACHE_LEAVES_END)
        .ok_or_else(|| "cache layout".to_string())?;
    let mac = qhs5_cache_mac(seed, body);
    if let Some(slot) = bytes.get_mut(QHS5_CACHE_LEAVES_END..QHS5_CACHE_BYTES) {
        slot.copy_from_slice(&mac);
    }
    write_atomic(&cache_path(private_path), &bytes, true)
}

fn read_qhs5_cache(path: &str, seed: &[u8; 64]) -> Option<[[u8; 64]; QHS5_LEAF_COUNT]> {
    let file = fs::File::open(path).ok()?;
    let limit = u64::try_from(QHS5_CACHE_BYTES).ok()?.saturating_add(1);
    let mut bytes = Vec::with_capacity(QHS5_CACHE_BYTES.saturating_add(1));
    let read = file.take(limit).read_to_end(&mut bytes).ok()?;
    if read != QHS5_CACHE_BYTES {
        return None;
    }
    if bytes.get(0..QHS_CACHE_HEADER_BYTES) != Some(QHS5_CACHE_HEADER.as_slice()) {
        return None;
    }
    let expected_fingerprint = qhs5_cache_fingerprint(seed);
    if bytes.get(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END)?
        != expected_fingerprint.as_slice()
    {
        return None;
    }
    let body = bytes.get(..QHS5_CACHE_LEAVES_END)?;
    let expected_mac = qhs5_cache_mac(seed, body);
    if bytes.get(QHS5_CACHE_LEAVES_END..QHS5_CACHE_BYTES)? != expected_mac.as_slice() {
        return None;
    }

    let mut leaves = [[0_u8; 64]; QHS5_LEAF_COUNT];
    for (destination, source) in leaves.iter_mut().zip(
        bytes
            .get(QHS5_CACHE_LEAVES_START..QHS5_CACHE_LEAVES_END)?
            .as_chunks::<QHS5_LEAF_BYTES>()
            .0
            .iter(),
    ) {
        destination.copy_from_slice(source);
    }
    Some(leaves)
}

fn qhs5_state_guard_mac(seed: &[u8; 64], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(QHS5_STATE_GUARD_MAC_CONTEXT, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn write_qhs5_state_guard(
    private_path: &str,
    seed: &[u8; 64],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    let mut body = [0_u8; 6];
    if let (Some(slot), Some(header)) = (body.get_mut(..4), key_bytes.get(..4)) {
        slot.copy_from_slice(header);
        if let Some(byte) = slot.get_mut(3) {
            *byte = 0;
        }
    } else {
        return Err("state guard layout".to_string());
    }
    if let Some(slot) = body.get_mut(4..6) {
        slot.copy_from_slice(&counter.to_le_bytes());
    }
    let mac = qhs5_state_guard_mac(seed, &body);
    let mut bytes = [0_u8; STATE_GUARD_BYTES];
    let (header, tag) = bytes.split_at_mut(6);
    header.copy_from_slice(&body);
    tag.copy_from_slice(&mac);
    write_atomic(&state_path(private_path), &bytes, true)
}

fn read_qhs5_state_guard(private_path: &str, seed: &[u8; 64]) -> Result<Option<[u8; 6]>, String> {
    let path = state_path(private_path);
    if !Path::new(&path).exists() {
        return Ok(None);
    }
    let bytes = read_exact_file(&path, STATE_GUARD_BYTES)?;
    let body = bytes
        .get(..6)
        .ok_or_else(|| "state guard layout".to_string())?;
    let expected = qhs5_state_guard_mac(seed, body);
    if bytes.get(6..) != Some(expected.as_slice()) {
        return Err("state guard is corrupt or belongs to a different key".to_string());
    }
    let mut output = [0_u8; 6];
    output.copy_from_slice(body);
    Ok(Some(output))
}

fn check_qhs5_state_guard(
    private_path: &str,
    seed: &[u8; 64],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    let guard = match read_qhs5_state_guard(private_path, seed) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            if counter > 0 {
                return Err(
                    "state guard is missing for an advanced key; restore the guard file"
                        .to_string(),
                );
            }
            return write_qhs5_state_guard(private_path, seed, key_bytes, counter);
        }
        Err(error) => return Err(error),
    };
    let Some(header) = key_bytes.get(..4) else {
        return Err("state guard key layout".to_string());
    };
    if guard.get(..4) != Some(header) {
        return Err("key state guard belongs to a different key".to_string());
    }
    let guard_counter = guard
        .get(4..6)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(0, u16::from_le_bytes);
    if guard_counter > counter {
        return Err(format!(
            "key state rollback detected: guard {guard_counter} > key {counter}"
        ));
    }
    if guard_counter < counter {
        write_qhs5_state_guard(private_path, seed, key_bytes, counter)?;
    }
    Ok(())
}

fn update_qhs5_state_guard(
    private_path: &str,
    seed: &[u8; 64],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    write_qhs5_state_guard(private_path, seed, key_bytes, counter)
}

fn qhs6_cache_fingerprint(seed: &[u8; 64]) -> [u8; 32] {
    derive_key32(QHS6_CACHE_FINGERPRINT_CONTEXT, seed).to_bytes()
}

fn qhs6_cache_mac(seed: &[u8; 64], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(QHS6_CACHE_MAC_CONTEXT, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn load_or_compute_leaves_v6(
    private_path: &str,
    seed: &[u8; 64],
) -> Result<[[u8; 64]; QHS5_LEAF_COUNT], String> {
    let path = cache_path(private_path);
    if let Some(leaves) = read_qhs6_cache(&path, seed) {
        return Ok(leaves);
    }
    let leaves = compute_leaves_for_cli_v5(seed)?;
    if let Err(error) = write_qhs6_cache(private_path, seed, &leaves) {
        eprintln!("qhs6-sign: warning: cache not written: {error}");
    }
    Ok(leaves)
}

fn write_qhs6_cache(
    private_path: &str,
    seed: &[u8; 64],
    leaves: &[[u8; 64]; QHS5_LEAF_COUNT],
) -> Result<(), String> {
    let mut bytes = vec![0_u8; QHS6_CACHE_BYTES];
    if let Some(slot) = bytes.get_mut(0..QHS_CACHE_HEADER_BYTES) {
        slot.copy_from_slice(&QHS6_CACHE_HEADER);
    }
    if let Some(slot) = bytes.get_mut(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END) {
        slot.copy_from_slice(&qhs6_cache_fingerprint(seed));
    }
    if let Some(slot) = bytes.get_mut(QHS6_CACHE_LEAVES_START..QHS6_CACHE_LEAVES_END) {
        for (destination, source) in slot
            .as_chunks_mut::<QHS5_LEAF_BYTES>()
            .0
            .iter_mut()
            .zip(leaves.iter())
        {
            destination.copy_from_slice(source);
        }
    }
    let body = bytes
        .get(..QHS6_CACHE_LEAVES_END)
        .ok_or_else(|| "cache layout".to_string())?;
    let mac = qhs6_cache_mac(seed, body);
    if let Some(slot) = bytes.get_mut(QHS6_CACHE_LEAVES_END..QHS6_CACHE_BYTES) {
        slot.copy_from_slice(&mac);
    }
    write_atomic(&cache_path(private_path), &bytes, true)
}

fn read_qhs6_cache(path: &str, seed: &[u8; 64]) -> Option<[[u8; 64]; QHS5_LEAF_COUNT]> {
    let file = fs::File::open(path).ok()?;
    let limit = u64::try_from(QHS6_CACHE_BYTES).ok()?.saturating_add(1);
    let mut bytes = Vec::with_capacity(QHS6_CACHE_BYTES.saturating_add(1));
    let read = file.take(limit).read_to_end(&mut bytes).ok()?;
    if read != QHS6_CACHE_BYTES {
        return None;
    }
    if bytes.get(0..QHS_CACHE_HEADER_BYTES) != Some(QHS6_CACHE_HEADER.as_slice()) {
        return None;
    }
    let expected_fingerprint = qhs6_cache_fingerprint(seed);
    if bytes.get(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END)?
        != expected_fingerprint.as_slice()
    {
        return None;
    }
    let body = bytes.get(..QHS6_CACHE_LEAVES_END)?;
    let expected_mac = qhs6_cache_mac(seed, body);
    if bytes.get(QHS6_CACHE_LEAVES_END..QHS6_CACHE_BYTES)? != expected_mac.as_slice() {
        return None;
    }

    let mut leaves = [[0_u8; 64]; QHS5_LEAF_COUNT];
    for (destination, source) in leaves.iter_mut().zip(
        bytes
            .get(QHS6_CACHE_LEAVES_START..QHS6_CACHE_LEAVES_END)?
            .as_chunks::<QHS5_LEAF_BYTES>()
            .0
            .iter(),
    ) {
        destination.copy_from_slice(source);
    }
    Some(leaves)
}

fn qhs6_state_guard_mac(seed: &[u8; 64], body: &[u8]) -> [u8; 32] {
    let key = derive_key32(QHS6_STATE_GUARD_MAC_CONTEXT, seed).to_bytes();
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(body);
    hasher.finalize().to_bytes()
}

fn write_qhs6_state_guard(
    private_path: &str,
    seed: &[u8; 64],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    let mut body = [0_u8; 6];
    if let (Some(slot), Some(header)) = (body.get_mut(..4), key_bytes.get(..4)) {
        slot.copy_from_slice(header);
        if let Some(byte) = slot.get_mut(3) {
            *byte = 0;
        }
    } else {
        return Err("state guard layout".to_string());
    }
    if let Some(slot) = body.get_mut(4..6) {
        slot.copy_from_slice(&counter.to_le_bytes());
    }
    let mac = qhs6_state_guard_mac(seed, &body);
    let mut bytes = [0_u8; STATE_GUARD_BYTES];
    let (header, tag) = bytes.split_at_mut(6);
    header.copy_from_slice(&body);
    tag.copy_from_slice(&mac);
    write_atomic(&state_path(private_path), &bytes, true)
}

fn read_qhs6_state_guard(private_path: &str, seed: &[u8; 64]) -> Result<Option<[u8; 6]>, String> {
    let path = state_path(private_path);
    if !Path::new(&path).exists() {
        return Ok(None);
    }
    let bytes = read_exact_file(&path, STATE_GUARD_BYTES)?;
    let body = bytes
        .get(..6)
        .ok_or_else(|| "state guard layout".to_string())?;
    let expected = qhs6_state_guard_mac(seed, body);
    if bytes.get(6..) != Some(expected.as_slice()) {
        return Err("state guard is corrupt or belongs to a different key".to_string());
    }
    let mut output = [0_u8; 6];
    output.copy_from_slice(body);
    Ok(Some(output))
}

fn check_qhs6_state_guard(
    private_path: &str,
    seed: &[u8; 64],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    let guard = match read_qhs6_state_guard(private_path, seed) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            if counter > 0 {
                return Err(
                    "state guard is missing for an advanced key; restore the guard file"
                        .to_string(),
                );
            }
            return write_qhs6_state_guard(private_path, seed, key_bytes, counter);
        }
        Err(error) => return Err(error),
    };
    let Some(header) = key_bytes.get(..4) else {
        return Err("state guard key layout".to_string());
    };
    if guard.get(..4) != Some(header) {
        return Err("key state guard belongs to a different key".to_string());
    }
    let guard_counter = guard
        .get(4..6)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(0, u16::from_le_bytes);
    if guard_counter > counter {
        return Err(format!(
            "key state rollback detected: guard {guard_counter} > key {counter}"
        ));
    }
    if guard_counter < counter {
        write_qhs6_state_guard(private_path, seed, key_bytes, counter)?;
    }
    Ok(())
}

fn update_qhs6_state_guard(
    private_path: &str,
    seed: &[u8; 64],
    key_bytes: &[u8],
    counter: u16,
) -> Result<(), String> {
    write_qhs6_state_guard(private_path, seed, key_bytes, counter)
}

struct Qhs31Tree {
    leaves: Vec<[u8; 32]>,
    nodes: Vec<[u8; 32]>,
}

fn qhs31_cache_path(private_path: &str) -> String {
    format!("{private_path}.treecache")
}

fn qhs31_cache_fingerprint(seed: &[u8; 32]) -> [u8; 32] {
    derive_key32(QHS31_TREE_CACHE_FINGERPRINT_CONTEXT, seed).to_bytes()
}

fn compute_tree_for_cli_v31(seed: &[u8; 32]) -> Result<Qhs31Tree, String> {
    let leaves = compute_leaves_for_cli_v3(seed)?;
    let mut nodes = vec![[0_u8; 32]; QHS3_TREE_NODES];
    let _root = qhs3_build_tree(&leaves, &mut nodes).map_err(|error| error.to_string())?;
    Ok(Qhs31Tree { leaves, nodes })
}

fn load_or_compute_tree_v31(private_path: &str, seed: &[u8; 32]) -> Result<Qhs31Tree, String> {
    let path = qhs31_cache_path(private_path);
    if let Some(tree) = read_qhs31_cache(&path, seed) {
        return Ok(tree);
    }
    let tree = compute_tree_for_cli_v31(seed)?;
    if let Err(error) = write_qhs31_cache(private_path, seed, &tree) {
        eprintln!("qhs31-sign: warning: tree cache not written: {error}");
    }
    Ok(tree)
}

fn write_qhs31_cache(private_path: &str, seed: &[u8; 32], tree: &Qhs31Tree) -> Result<(), String> {
    if tree.leaves.len() != QHS3_LEAF_COUNT || tree.nodes.len() != QHS3_TREE_NODES {
        return Err("tree cache layout".to_string());
    }
    let mut bytes = vec![0_u8; QHS31_TREE_CACHE_BYTES];
    if let Some(slot) = bytes.get_mut(0..QHS_CACHE_HEADER_BYTES) {
        slot.copy_from_slice(&QHS31_TREE_CACHE_HEADER);
    }
    if let Some(slot) = bytes.get_mut(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END) {
        slot.copy_from_slice(&qhs31_cache_fingerprint(seed));
    }
    if let Some(slot) = bytes.get_mut(QHS31_TREE_CACHE_LEAVES_START..QHS31_TREE_CACHE_LEAVES_END) {
        for (destination, source) in slot
            .as_chunks_mut::<QHS_LEAF_BYTES>()
            .0
            .iter_mut()
            .zip(tree.leaves.iter())
        {
            destination.copy_from_slice(source);
        }
    }
    if let Some(slot) = bytes.get_mut(QHS31_TREE_CACHE_NODES_START..QHS31_TREE_CACHE_NODES_END) {
        for (destination, source) in slot
            .as_chunks_mut::<QHS_LEAF_BYTES>()
            .0
            .iter_mut()
            .zip(tree.nodes.iter())
        {
            destination.copy_from_slice(source);
        }
    }
    let body = bytes
        .get(..QHS31_TREE_CACHE_NODES_END)
        .ok_or_else(|| "tree cache layout".to_string())?;
    let mac = cache_mac(seed, QHS31_TREE_CACHE_MAC_CONTEXT, body);
    if let Some(slot) = bytes.get_mut(QHS31_TREE_CACHE_NODES_END..QHS31_TREE_CACHE_BYTES) {
        slot.copy_from_slice(&mac);
    }
    write_atomic(&qhs31_cache_path(private_path), &bytes, true)
}

fn read_qhs31_cache(path: &str, seed: &[u8; 32]) -> Option<Qhs31Tree> {
    let file = fs::File::open(path).ok()?;
    let limit = u64::try_from(QHS31_TREE_CACHE_BYTES)
        .ok()?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(QHS31_TREE_CACHE_BYTES.saturating_add(1));
    let read = file.take(limit).read_to_end(&mut bytes).ok()?;
    if read != QHS31_TREE_CACHE_BYTES {
        return None;
    }
    if bytes.get(0..QHS_CACHE_HEADER_BYTES) != Some(QHS31_TREE_CACHE_HEADER.as_slice()) {
        return None;
    }
    let expected_fingerprint = qhs31_cache_fingerprint(seed);
    if bytes.get(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END)?
        != expected_fingerprint.as_slice()
    {
        return None;
    }
    let body = bytes.get(..QHS31_TREE_CACHE_NODES_END)?;
    let expected_mac = cache_mac(seed, QHS31_TREE_CACHE_MAC_CONTEXT, body);
    if bytes.get(QHS31_TREE_CACHE_NODES_END..QHS31_TREE_CACHE_BYTES)? != expected_mac.as_slice() {
        return None;
    }

    let mut leaves = Vec::with_capacity(QHS3_LEAF_COUNT);
    for chunk in bytes
        .get(QHS31_TREE_CACHE_LEAVES_START..QHS31_TREE_CACHE_LEAVES_END)?
        .as_chunks::<QHS_LEAF_BYTES>()
        .0
    {
        leaves.push(*chunk);
    }
    let mut nodes = Vec::with_capacity(QHS3_TREE_NODES);
    for chunk in bytes
        .get(QHS31_TREE_CACHE_NODES_START..QHS31_TREE_CACHE_NODES_END)?
        .as_chunks::<QHS_LEAF_BYTES>()
        .0
    {
        nodes.push(*chunk);
    }
    Some(Qhs31Tree { leaves, nodes })
}

fn read_exact_file(path: &str, expected: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|error| format!("{path}: {error}"))?;
    let limit = u64::try_from(expected)
        .map_err(|_| format!("{path}: invalid expected length"))?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(expected.saturating_add(1));
    let read = file
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{path}: {error}"))?;
    if read != expected {
        return Err(format!("{path}: expected {expected} bytes, got {read}"));
    }
    Ok(bytes)
}

#[allow(
    unused_results,
    reason = "OpenOptions builder methods return &mut Self and are used for side effects"
)]
fn write_atomic(path: &str, bytes: &[u8], private: bool) -> Result<(), String> {
    let target = Path::new(path);
    let temporary = target.with_extension("tmp");
    if let Err(error) = fs::remove_file(&temporary)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(format!("{}: {error}", temporary.display()));
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        if private {
            options.mode(0o600);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = private;
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("{}: {error}", temporary.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("{}: {error}", temporary.display()))?;
    file.sync_all()
        .map_err(|error| format!("{}: {error}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, target).map_err(|error| format!("{path}: {error}"))?;
    Ok(())
}

fn run_named_selftest(name: &str, selftest: fn() -> bool) -> ExitCode {
    if selftest() {
        println!("{name}: ok");
        ExitCode::SUCCESS
    } else {
        eprintln!("{name}: failed");
        ExitCode::from(3)
    }
}

fn all_true(checks: &[bool]) -> bool {
    checks.iter().all(|value| *value)
}

fn qhs2_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok((mut private_key, public_key)) = qhs2_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = private_key.sign(b"qhs2-selftest") else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs2-selftest", &signature).is_ok(),
        public_key.verify(b"qhs2-wrong", &signature).is_err(),
    ])
}

fn qhs3_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok(leaves) = qhs3_leaves_parallel(&seed) else {
        return false;
    };
    let Ok((mut private_key, public_key)) = qhs3_keygen_from_leaves(&seed, &leaves) else {
        return false;
    };
    let Ok(signature) = private_key.sign_with_leaves(b"qhs3-selftest", &leaves) else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs3-selftest", &signature).is_ok(),
        public_key.verify(b"qhs3-wrong", &signature).is_err(),
    ])
}

fn qhs31_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok(tree) = compute_tree_for_cli_v31(&seed) else {
        return false;
    };
    let Ok((mut private_key, public_key)) = qhs3_keygen_from_leaves(&seed, &tree.leaves) else {
        return false;
    };
    let Ok(auth_path) = qhs3_auth_path_from_tree(&tree.leaves, &tree.nodes, 0) else {
        return false;
    };
    let Ok(signature) = private_key.sign_with_auth_path(b"qhs31-selftest", &auth_path) else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs31-selftest", &signature).is_ok(),
        public_key.verify(b"qhs31-wrong", &signature).is_err(),
    ])
}

fn qhs4_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok((private_key, public_key)) = qhs4_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = private_key.sign(b"qhs4-selftest") else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs4-selftest", &signature).is_ok(),
        public_key.verify(b"qhs4-wrong", &signature).is_err(),
    ])
}

fn qhs41_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok((private_key, public_key)) = qhs4_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = qhs4_sign_parallel(&private_key, b"qhs41-selftest") else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs41-selftest", &signature).is_ok(),
        public_key.verify(b"qhs41-wrong", &signature).is_err(),
    ])
}

fn qhs42_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok((private_key, public_key)) = qhs42_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = qhs42_sign_parallel(&private_key, b"qhs42-selftest") else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs42-selftest", &signature).is_ok(),
        public_key.verify(b"qhs42-wrong", &signature).is_err(),
    ])
}

fn qhs5_selftest() -> bool {
    let seed = [7_u8; 64];
    let Ok(leaves) = compute_leaves_for_cli_v5(&seed) else {
        return false;
    };
    let Ok((mut private_key, public_key)) = qhs5_keygen_from_leaves(&seed, &leaves) else {
        return false;
    };
    let Ok(signature) = private_key.sign_with_leaves(b"qhs5-selftest", &leaves) else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs5-selftest", &signature).is_ok(),
        public_key.verify(b"qhs5-wrong", &signature).is_err(),
        private_key.next_leaf() == 1,
    ])
}

fn qhs6_selftest() -> bool {
    let qhs5_seed = [7_u8; 64];
    let ed25519_seed = [9_u8; 32];
    let Ok(leaves) = compute_leaves_for_cli_v5(&qhs5_seed) else {
        return false;
    };
    let Ok((mut private_key, public_key)) =
        qhs6_keygen_from_leaves(&qhs5_seed, &ed25519_seed, &leaves)
    else {
        return false;
    };
    let Ok(signature) = private_key.sign_with_leaves(b"qhs6-selftest", &leaves) else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs6-selftest", &signature).is_ok(),
        public_key.verify(b"qhs6-wrong", &signature).is_err(),
        private_key.next_leaf() == 1,
    ])
}

fn braid_selftest(value: &Braid) -> bool {
    let bytes = value.to_bytes();
    value.len() == 3
        && bytes.first() == Some(&1)
        && bytes.get(1) == Some(&0xfe)
        && bytes.get(2) == Some(&7)
        && Braid::from_bytes(&bytes).is_ok_and(|parsed| parsed == *value)
}

fn qhs_selftest() -> bool {
    let seed = [7_u8; 32];
    let Ok((mut private_key, public_key)) = qhs_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = private_key.sign(b"qhs-selftest") else {
        return false;
    };
    all_true(&[
        public_key.verify(b"qhs-selftest", &signature).is_ok(),
        public_key.verify(b"qhs-wrong", &signature).is_err(),
    ])
}

fn selftest() -> bool {
    let braid = Braid::from_generators(&[1, -2, 7]);
    let braid_ok = braid.is_ok_and(|value| braid_selftest(&value));

    let mut polynomial = Polynomial::new();
    let polynomial_ok = all_true(&[
        polynomial.set_coefficient(0, 42).is_ok(),
        polynomial.coefficient(0) == Ok(42),
        Polynomial::from_bytes(&polynomial.to_bytes()) == polynomial,
    ]);

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

    all_true(&[
        braid_ok,
        polynomial_ok,
        private_key_ok,
        public_key_ok,
        signature_ok,
        hash_ok,
        size_of::<Braid>() == BRAID_BYTES,
        size_of::<Polynomial>() == PUBLIC_KEY_BYTES,
        size_of::<Signature>() == SIGNATURE_BYTES,
    ])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "tests use fixed valid fixtures and expect construction to succeed"
    )]

    use super::{
        Braid, QHS3_LEAF_COUNT, QHS3_TREE_NODES, Qhs31Tree, all_true, braid_selftest,
        check_state_guard, read_state_guard, write_qhs31_cache, write_state_guard,
    };

    #[test]
    fn all_true_requires_every_check() {
        assert!(all_true(&[true, true]));
        assert!(!all_true(&[true, false]));
        assert!(!all_true(&[false, true]));
    }

    #[test]
    fn state_guard_advances_when_behind() {
        let seed = [7_u8; 32];
        let path =
            std::env::temp_dir().join(format!("qwp-state-guard-test-{}", std::process::id()));
        let path_text = path.to_string_lossy().to_string();
        drop(std::fs::remove_file(&path_text));
        let mut key_bytes = [0_u8; 64];
        key_bytes[..4].copy_from_slice(&[3, 3, 12, 0]);

        write_state_guard(&path_text, &seed, &key_bytes, 0).unwrap();
        check_state_guard(&path_text, &seed, &key_bytes, 1).unwrap();
        let guard = read_state_guard(&path_text, &seed).unwrap().unwrap();
        assert_eq!(u16::from_le_bytes([guard[4], guard[5]]), 1);

        drop(std::fs::remove_file(&path_text));
    }

    #[test]
    fn tree_cache_rejects_bad_lengths() {
        let seed = [7_u8; 32];
        let short_leaves = Qhs31Tree {
            leaves: vec![[0_u8; 32]; QHS3_LEAF_COUNT - 1],
            nodes: vec![[0_u8; 32]; QHS3_TREE_NODES],
        };
        assert!(write_qhs31_cache("unused", &seed, &short_leaves).is_err());
        let short_nodes = Qhs31Tree {
            leaves: vec![[0_u8; 32]; QHS3_LEAF_COUNT],
            nodes: vec![[0_u8; 32]; QHS3_TREE_NODES - 1],
        };
        assert!(write_qhs31_cache("unused", &seed, &short_nodes).is_err());
    }

    #[test]
    fn braid_selftest_rejects_wrong_word() {
        let good = Braid::from_generators(&[1, -2, 7]).unwrap();
        assert!(braid_selftest(&good));
        let wrong = Braid::from_generators(&[1, 2, 7]).unwrap();
        assert!(!braid_selftest(&wrong));
    }
}
