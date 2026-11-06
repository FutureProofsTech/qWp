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
    QHS_PUBLIC_KEY_BYTES, QHS_SIGNATURE_BYTES, QhsPrivateKey, QhsPublicKey, QhsSignature,
    Signature, qhs_keygen, qhs_keygen_from_leaves, qhs_leaves,
};
use qwp_hash::{derive_key32, hash32};
use qwp_platform::{HostEntropy, qhs_leaves_parallel};

const QHS_CACHE_HEADER_BYTES: usize = 4;
const QHS_CACHE_CHECKSUM_BYTES: usize = 4;
const QHS_CACHE_BYTES: usize = 8232;
const QHS_CACHE_FINGERPRINT_START: usize = 4;
const QHS_CACHE_FINGERPRINT_END: usize = 36;
const QHS_CACHE_LEAVES_START: usize = 36;
const QHS_CACHE_LEAVES_END: usize = 8228;
const QHS_CACHE_CHECKSUM_START: usize = 8228;
const QHS_CACHE_FINGERPRINT_CONTEXT: &[u8] = b"qWp QHS-1 cache fingerprint";

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
        Some("qhs-selftest") => {
            if qhs_selftest() {
                println!("qhs-selftest: ok");
                ExitCode::SUCCESS
            } else {
                eprintln!("qhs-selftest: failed");
                ExitCode::from(3)
            }
        }
        Some("qhs-keygen") => run_qhs_keygen(&arguments),
        Some("qhs-sign") => run_qhs_sign(&arguments),
        Some("qhs-verify") => run_qhs_verify(&arguments),
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
    println!("  qhs-verify <pub> <message> <sig> verify signature");
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
    match qhs_keygen_from_leaves(&seed, &leaves) {
        Ok((private_key, public_key)) => {
            if let Err(error) = write_atomic(private_path, &private_key.to_bytes(), true) {
                eprintln!("qhs-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_atomic(public_path, &public_key.to_bytes(), false) {
                eprintln!("qhs-keygen: {error}");
                return ExitCode::from(3);
            }
            if let Err(error) = write_qhs_cache(private_path, &seed, &leaves) {
                eprintln!("qhs-keygen: warning: cache not written: {error}");
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
    let leaves = match load_or_compute_leaves(private_path, &seed) {
        Ok(leaves) => leaves,
        Err(error) => {
            eprintln!("qhs-sign: {error}");
            return ExitCode::from(3);
        }
    };
    let signature = match private_key.sign_with_leaves(&message, &leaves) {
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

fn cache_fingerprint(seed: &[u8; 32]) -> [u8; 32] {
    derive_key32(QHS_CACHE_FINGERPRINT_CONTEXT, seed).to_bytes()
}

fn compute_leaves_for_cli(seed: &[u8; 32]) -> Result<[[u8; 32]; QHS_LEAF_COUNT], String> {
    qhs_leaves_parallel(seed)
        .map_or_else(|_| qhs_leaves(seed).map_err(|error| error.to_string()), Ok)
}

fn load_or_compute_leaves(
    private_path: &str,
    seed: &[u8; 32],
) -> Result<[[u8; 32]; QHS_LEAF_COUNT], String> {
    let path = cache_path(private_path);
    if let Some(leaves) = read_qhs_cache(&path, seed) {
        return Ok(leaves);
    }
    let leaves = compute_leaves_for_cli(seed)?;
    if let Err(error) = write_qhs_cache(private_path, seed, &leaves) {
        eprintln!("qhs-sign: warning: cache not written: {error}");
    }
    Ok(leaves)
}

fn write_qhs_cache(
    private_path: &str,
    seed: &[u8; 32],
    leaves: &[[u8; 32]; QHS_LEAF_COUNT],
) -> Result<(), String> {
    let mut bytes = [0_u8; QHS_CACHE_BYTES];
    if let Some(slot) = bytes.get_mut(0..QHS_CACHE_HEADER_BYTES) {
        slot.copy_from_slice(&[1, 1, 8, 0]);
    }
    if let Some(slot) = bytes.get_mut(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END) {
        slot.copy_from_slice(&cache_fingerprint(seed));
    }
    let leaves_start = QHS_CACHE_LEAVES_START;
    let leaves_end = QHS_CACHE_LEAVES_END;
    if let Some(slot) = bytes.get_mut(leaves_start..leaves_end) {
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
    let checksum = hash32(body).to_bytes();
    if let Some(slot) = bytes.get_mut(QHS_CACHE_CHECKSUM_START..QHS_CACHE_BYTES) {
        slot.copy_from_slice(
            checksum
                .get(..QHS_CACHE_CHECKSUM_BYTES)
                .ok_or_else(|| "cache checksum".to_string())?,
        );
    }
    write_atomic(&cache_path(private_path), &bytes, true)
}

fn read_qhs_cache(path: &str, seed: &[u8; 32]) -> Option<[[u8; 32]; QHS_LEAF_COUNT]> {
    let file = fs::File::open(path).ok()?;
    let limit = u64::try_from(QHS_CACHE_BYTES).ok()?.saturating_add(1);
    let mut bytes = Vec::with_capacity(QHS_CACHE_BYTES.saturating_add(1));
    let read = file.take(limit).read_to_end(&mut bytes).ok()?;
    if read != QHS_CACHE_BYTES {
        return None;
    }
    if bytes.first() != Some(&1)
        || bytes.get(1) != Some(&1)
        || bytes.get(2) != Some(&8)
        || bytes.get(3) != Some(&0)
    {
        return None;
    }
    let expected_fingerprint = cache_fingerprint(seed);
    if bytes.get(QHS_CACHE_FINGERPRINT_START..QHS_CACHE_FINGERPRINT_END)?
        != expected_fingerprint.as_slice()
    {
        return None;
    }
    let leaves_start = QHS_CACHE_LEAVES_START;
    let leaves_end = QHS_CACHE_LEAVES_END;
    let body = bytes.get(..leaves_end)?;
    let expected_checksum = hash32(body).to_bytes();
    if bytes.get(QHS_CACHE_CHECKSUM_START..QHS_CACHE_BYTES)?
        != expected_checksum.get(..QHS_CACHE_CHECKSUM_BYTES)?
    {
        return None;
    }

    let mut leaves = [[0_u8; 32]; QHS_LEAF_COUNT];
    for (slot, chunk) in leaves.iter_mut().zip(
        bytes
            .get(leaves_start..leaves_end)?
            .as_chunks::<QHS_LEAF_BYTES>()
            .0,
    ) {
        *slot = *chunk;
    }
    Some(leaves)
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

fn all_true(checks: &[bool]) -> bool {
    checks.iter().all(|value| *value)
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

    use super::{Braid, all_true, braid_selftest};

    #[test]
    fn all_true_requires_every_check() {
        assert!(all_true(&[true, true]));
        assert!(!all_true(&[true, false]));
        assert!(!all_true(&[false, true]));
    }

    #[test]
    fn braid_selftest_rejects_wrong_word() {
        let good = Braid::from_generators(&[1, -2, 7]).unwrap();
        assert!(braid_selftest(&good));
        let wrong = Braid::from_generators(&[1, 2, 7]).unwrap();
        assert!(!braid_selftest(&wrong));
    }
}
