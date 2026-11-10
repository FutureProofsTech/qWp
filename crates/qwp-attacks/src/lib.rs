//! qWp attacker-side harnesses.
//!
//! These functions are deliberately adversarial: they feed malformed input,
//! boundary values, and misuse cases to the qWp foundation.

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
    reason = "the attack harness intentionally uses std for reporting and file checks"
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
#![deny(clippy::exit)]
#![deny(clippy::mem_forget)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::let_underscore_must_use)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
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

use std::fs;
use std::path::Path;

use qwp_core::{BRAID_BYTES, Braid, CryptoError, MAX_CROSSINGS, Polynomial};
use qwp_crypto::{
    PrivateKey, PublicKey, QHS_MAX_SIGNATURES, QHS2_MAX_SIGNATURES, QHS3_MAX_SIGNATURES,
    QHS4_SIGNATURE_BYTES, QHS5_MAX_SIGNATURES, QHS6_SIGNATURE_BYTES, Qhs2PrivateKey, Qhs2Signature,
    Qhs3PrivateKey, Qhs3PublicKey, Qhs3Signature, Qhs4PublicKey, Qhs4Signature, Qhs5PrivateKey,
    Qhs5Signature, Qhs6PrivateKey, Qhs6Signature, Qhs42PublicKey, Qhs42Signature, QhsPrivateKey,
    QhsSignature, Signature, qhs_keygen, qhs2_keygen, qhs3_keygen, qhs3_keygen_from_leaves,
    qhs4_keygen, qhs5_keygen, qhs6_keygen, qhs42_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};
use qwp_hash::hash32;
use qwp_platform::{HostEntropy, qhs3_leaves_parallel, qhs4_sign_parallel, qhs42_sign_parallel};

/// Summary of an attack run.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackReport {
    /// Number of attacks that passed.
    pub passed: usize,
    /// Number of attacks that failed.
    pub failed: usize,
}

impl AttackReport {
    /// Returns `true` when every attack passed.
    #[must_use]
    #[inline]
    pub const fn is_ok(self) -> bool {
        self.failed == 0
    }
}

/// Summary of the documentation/process audit.
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the audit report mirrors five independent artifact checks"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditReport {
    /// `docs/adversary/index.md` exists.
    pub fad_index: bool,
    /// `docs/gap-register.md` exists.
    pub gap_register: bool,
    /// `docs/traceability.md` exists.
    pub traceability: bool,
    /// `docs/break-log.md` exists.
    pub break_log: bool,
    /// `docs/attack-trees.md` exists.
    pub attack_trees: bool,
}

impl AuditReport {
    /// Returns `true` when every required artifact exists.
    #[must_use]
    #[inline]
    pub const fn is_ok(self) -> bool {
        self.fad_index
            && self.gap_register
            && self.traceability
            && self.break_log
            && self.attack_trees
    }
}

/// Runs every attack harness.
#[must_use]
#[inline]
pub fn run_all() -> AttackReport {
    let checks = [
        attack_braid_parser(),
        attack_polynomial_round_trip(),
        attack_key_formats(),
        attack_hash_vectors(),
        attack_entropy(),
        attack_qhs1(),
        attack_qhs2(),
        attack_qhs3(),
        attack_qhs4(),
        attack_qhs41(),
        attack_qhs42(),
        attack_qhs5(),
        attack_qhs6(),
        attack_qhse(),
    ];
    let passed = checks.iter().filter(|result| **result).count();
    let failed = checks.len().saturating_sub(passed);
    AttackReport { passed, failed }
}

/// Audits the presence of the qWp process artifacts.
///
/// # Errors
///
/// Returns an I/O error if a required file cannot be inspected.
#[inline]
pub fn audit() -> Result<AuditReport, std::io::Error> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Ok(AuditReport {
        fad_index: path_exists(&root.join("docs/adversary/index.md"))?,
        gap_register: path_exists(&root.join("docs/gap-register.md"))?,
        traceability: path_exists(&root.join("docs/traceability.md"))?,
        break_log: path_exists(&root.join("docs/break-log.md"))?,
        attack_trees: path_exists(&root.join("docs/attack-trees.md"))?,
    })
}

fn path_exists(path: &Path) -> Result<bool, std::io::Error> {
    let metadata = fs::metadata(path);
    match metadata {
        Ok(value) => Ok(value.is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Attacks the braid parser with malformed lengths, generators, and padding.
#[must_use]
#[inline]
pub fn attack_braid_parser() -> bool {
    let valid = Braid::from_generators(&[1, -2, 7]);
    let valid_round_trip = valid.is_ok_and(|braid| {
        let bytes = braid.to_bytes();
        Braid::from_bytes(&bytes).is_ok_and(|parsed| parsed == braid)
    });

    let mut bad_padding = [0_u8; BRAID_BYTES];
    bad_padding[0] = 1;
    bad_padding[1] = 0;
    let bad_padding_rejected = Braid::from_bytes(&bad_padding) == Err(CryptoError::InvalidPadding);

    let mut bad_length = [0_u8; BRAID_BYTES];
    let length = u64::try_from(MAX_CROSSINGS).unwrap_or(0).saturating_add(1);
    bad_length[32..40].copy_from_slice(&length.to_le_bytes());
    let bad_length_rejected = Braid::from_bytes(&bad_length) == Err(CryptoError::InvalidLength);

    let mut bad_generator = [0_u8; BRAID_BYTES];
    bad_generator[0] = 8;
    bad_generator[32..40].copy_from_slice(&1_u64.to_le_bytes());
    let bad_generator_rejected =
        Braid::from_bytes(&bad_generator) == Err(CryptoError::InvalidGenerator);

    valid_round_trip && bad_padding_rejected && bad_length_rejected && bad_generator_rejected
}

/// Attacks the polynomial parser with a deterministic full-range pattern.
#[must_use]
#[inline]
pub fn attack_polynomial_round_trip() -> bool {
    let mut bytes = [0_u8; qwp_core::PUBLIC_KEY_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index & 0xff).unwrap_or(0);
    }
    let polynomial = Polynomial::from_bytes(&bytes);
    polynomial.to_bytes() == bytes
}

/// Attacks the fixed-size key and signature formats.
#[must_use]
#[inline]
pub fn attack_key_formats() -> bool {
    let braid = Braid::from_generators(&[1, -2, 7]);
    let private_key_ok = braid.is_ok_and(|value| {
        let key = PrivateKey::from_braid(value);
        PrivateKey::from_bytes(&key.to_bytes()).is_ok_and(|parsed| parsed.len() == 3)
    });

    let public_key = PublicKey::from_polynomial(Polynomial::new());
    let public_key_ok = PublicKey::from_bytes(&public_key.to_bytes()) == public_key;

    let signature = Signature::from_bytes([0_u8; qwp_core::SIGNATURE_BYTES]);
    let signature_ok = Signature::from_bytes(signature.to_bytes()) == signature;

    private_key_ok && public_key_ok && signature_ok
}

/// Attacks the hash implementation with published vectors.
#[must_use]
#[inline]
pub fn attack_hash_vectors() -> bool {
    let empty = hash32(b"");
    let abc = hash32(b"abc");
    std::format!("{empty:?}")
        == "Hash32(af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262)"
        && std::format!("{abc:?}")
            == "Hash32(6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85)"
}

/// Attacks the host entropy adapter with zero-length and normal requests.
#[must_use]
#[inline]
pub fn attack_entropy() -> bool {
    HostEntropy::open().is_ok_and(|mut entropy| {
        let mut output = [0_u8; 16];
        entropy.fill(&mut output).is_ok() && entropy.fill(&mut []).is_ok()
    })
}

/// Attacks QHS-1 with wrong messages, tampering, wrong keys, and exhaustion.
#[must_use]
#[inline]
pub fn attack_qhs1() -> bool {
    let seed = [7_u8; 32];
    let Ok((mut private_key, public_key)) = qhs_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = private_key.sign(b"qhs-attack-message") else {
        return false;
    };
    let accepted = public_key.verify(b"qhs-attack-message", &signature).is_ok();
    let wrong_message = public_key.verify(b"qhs-wrong-message", &signature).is_err();

    let tamper_offsets = [0_usize, 1, 2, 3, 10, 2148, 2404];
    let mut tampered_rejected = true;
    for offset in tamper_offsets {
        let mut tampered_bytes = signature.to_bytes();
        if let Some(byte) = tampered_bytes.get_mut(offset) {
            *byte ^= 1;
        }
        let tampered = QhsSignature::from_bytes(tampered_bytes);
        if public_key.verify(b"qhs-attack-message", &tampered).is_ok() {
            tampered_rejected = false;
            break;
        }
    }
    let zero_rejected = public_key
        .verify(
            b"qhs-attack-message",
            &QhsSignature::from_bytes([0_u8; qwp_crypto::QHS_SIGNATURE_BYTES]),
        )
        .is_err();
    let ff_rejected = public_key
        .verify(
            b"qhs-attack-message",
            &QhsSignature::from_bytes([0xff_u8; qwp_crypto::QHS_SIGNATURE_BYTES]),
        )
        .is_err();

    let Ok((_, other_public_key)) = qhs_keygen(&[9_u8; 32]) else {
        return false;
    };
    let wrong_key = other_public_key
        .verify(b"qhs-attack-message", &signature)
        .is_err();

    let mut key_bytes = private_key.to_bytes();
    if let Some(slot) = key_bytes.get_mut(36..38) {
        slot.copy_from_slice(&QHS_MAX_SIGNATURES.to_le_bytes());
    }
    let exhausted_ok = QhsPrivateKey::from_bytes(&key_bytes)
        .is_ok_and(|mut exhausted| exhausted.sign(b"message") == Err(CryptoError::KeyExhausted));

    accepted
        && wrong_message
        && tampered_rejected
        && wrong_key
        && exhausted_ok
        && zero_rejected
        && ff_rejected
}

/// Attacks QHS-2 with wrong messages, tampering, wrong keys, and exhaustion.
#[must_use]
#[inline]
pub fn attack_qhs2() -> bool {
    let seed = [7_u8; 32];
    let Ok((mut private_key, public_key)) = qhs2_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = private_key.sign(b"qhs2-attack-message") else {
        return false;
    };
    let accepted = public_key
        .verify(b"qhs2-attack-message", &signature)
        .is_ok();
    let wrong_message = public_key
        .verify(b"qhs2-wrong-message", &signature)
        .is_err();

    let tamper_offsets = [0_usize, 1, 2, 3, 10, 1444, 1700];
    let mut tampered_rejected = true;
    for offset in tamper_offsets {
        let mut tampered_bytes = signature.to_bytes();
        if let Some(byte) = tampered_bytes.get_mut(offset) {
            *byte ^= 1;
        }
        let tampered = Qhs2Signature::from_bytes(tampered_bytes);
        if public_key.verify(b"qhs2-attack-message", &tampered).is_ok() {
            tampered_rejected = false;
            break;
        }
    }
    let zero_rejected = public_key
        .verify(
            b"qhs2-attack-message",
            &Qhs2Signature::from_bytes([0_u8; qwp_crypto::QHS2_SIGNATURE_BYTES]),
        )
        .is_err();
    let ff_rejected = public_key
        .verify(
            b"qhs2-attack-message",
            &Qhs2Signature::from_bytes([0xff_u8; qwp_crypto::QHS2_SIGNATURE_BYTES]),
        )
        .is_err();

    let Ok((_, other_public_key)) = qhs2_keygen(&[9_u8; 32]) else {
        return false;
    };
    let wrong_key = other_public_key
        .verify(b"qhs2-attack-message", &signature)
        .is_err();

    let mut key_bytes = private_key.to_bytes();
    if let Some(slot) = key_bytes.get_mut(36..38) {
        slot.copy_from_slice(&QHS2_MAX_SIGNATURES.to_le_bytes());
    }
    let exhausted_ok = Qhs2PrivateKey::from_bytes(&key_bytes)
        .is_ok_and(|mut exhausted| exhausted.sign(b"message") == Err(CryptoError::KeyExhausted));

    accepted
        && wrong_message
        && tampered_rejected
        && wrong_key
        && exhausted_ok
        && zero_rejected
        && ff_rejected
}

/// Attacks QHS-3 with wrong messages, tampering, wrong keys, and exhaustion.
#[must_use]
#[inline]
pub fn attack_qhs3() -> bool {
    let seed = [7_u8; 32];
    let Ok(leaves) = qhs3_leaves_parallel(&seed) else {
        return false;
    };
    let Ok((mut private_key, public_key)) = qhs3_keygen_from_leaves(&seed, &leaves) else {
        return false;
    };
    let Ok(signature) = private_key.sign_with_leaves(b"qhs3-attack-message", &leaves) else {
        return false;
    };
    let accepted = public_key
        .verify(b"qhs3-attack-message", &signature)
        .is_ok();
    let wrong_message = public_key
        .verify(b"qhs3-wrong-message", &signature)
        .is_err();

    let tamper_offsets = [0_usize, 1, 2, 3, 10, 1444, 1700];
    let mut tampered_rejected = true;
    for offset in tamper_offsets {
        let mut tampered_bytes = signature.to_bytes();
        if let Some(byte) = tampered_bytes.get_mut(offset) {
            *byte ^= 1;
        }
        let tampered = Qhs3Signature::from_bytes(tampered_bytes);
        if public_key.verify(b"qhs3-attack-message", &tampered).is_ok() {
            tampered_rejected = false;
            break;
        }
    }
    let zero_rejected = public_key
        .verify(
            b"qhs3-attack-message",
            &Qhs3Signature::from_bytes([0_u8; qwp_crypto::QHS3_SIGNATURE_BYTES]),
        )
        .is_err();
    let ff_rejected = public_key
        .verify(
            b"qhs3-attack-message",
            &Qhs3Signature::from_bytes([0xff_u8; qwp_crypto::QHS3_SIGNATURE_BYTES]),
        )
        .is_err();

    let mut wrong_bytes = public_key.to_bytes();
    wrong_bytes[4] ^= 1;
    let wrong_key = Qhs3PublicKey::from_bytes(&wrong_bytes)
        .is_ok_and(|other| other.verify(b"qhs3-attack-message", &signature).is_err());

    let mut key_bytes = private_key.to_bytes();
    if let Some(slot) = key_bytes.get_mut(36..38) {
        slot.copy_from_slice(&QHS3_MAX_SIGNATURES.to_le_bytes());
    }
    let exhausted_ok = Qhs3PrivateKey::from_bytes(&key_bytes)
        .is_ok_and(|mut exhausted| exhausted.sign(b"message") == Err(CryptoError::KeyExhausted));

    accepted
        && wrong_message
        && tampered_rejected
        && wrong_key
        && exhausted_ok
        && zero_rejected
        && ff_rejected
}

/// Attacks QHS-4 with wrong messages, tampering, wrong keys, and statelessness checks.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    reason = "the fixed QHS-4 signature is 18,216 bytes"
)]
pub fn attack_qhs4() -> bool {
    let seed = [7_u8; 32];
    let Ok((private_key, public_key)) = qhs4_keygen(&seed) else {
        return false;
    };
    let key_before = private_key.to_bytes();
    let Ok(signature) = private_key.sign(b"qhs4-attack-message") else {
        return false;
    };
    let key_after = private_key.to_bytes();
    let stateless = key_before == key_after;
    let accepted = public_key
        .verify(b"qhs4-attack-message", &signature)
        .is_ok();
    let wrong_message = public_key
        .verify(b"qhs4-wrong-message", &signature)
        .is_err();
    let deterministic = private_key
        .sign(b"qhs4-attack-message")
        .is_ok_and(|again| again == signature);

    let tamper_offsets = [
        0_usize, 1, 2, 3, 4, 35, 36, 100, 4_644, 6_000, 18_000, 18_215,
    ];
    let mut tampered_rejected = true;
    for offset in tamper_offsets {
        let mut tampered_bytes = signature.to_bytes();
        if let Some(byte) = tampered_bytes.get_mut(offset) {
            *byte ^= 1;
        }
        let tampered = Qhs4Signature::from_bytes(tampered_bytes);
        if public_key.verify(b"qhs4-attack-message", &tampered).is_ok() {
            tampered_rejected = false;
            break;
        }
    }
    let zero_rejected = public_key
        .verify(
            b"qhs4-attack-message",
            &Qhs4Signature::from_bytes([0_u8; QHS4_SIGNATURE_BYTES]),
        )
        .is_err();
    let ff_rejected = public_key
        .verify(
            b"qhs4-attack-message",
            &Qhs4Signature::from_bytes([0xff_u8; QHS4_SIGNATURE_BYTES]),
        )
        .is_err();

    let mut wrong_public_bytes = public_key.to_bytes();
    if let Some(byte) = wrong_public_bytes.get_mut(4) {
        *byte ^= 1;
    }
    let wrong_key = Qhs4PublicKey::from_bytes(&wrong_public_bytes)
        .is_ok_and(|other| other.verify(b"qhs4-attack-message", &signature).is_err());

    let mut wrong_header_bytes = signature.to_bytes();
    if let Some(byte) = wrong_header_bytes.get_mut(0) {
        *byte = 3;
    }
    let wrong_header = Qhs4Signature::from_bytes(wrong_header_bytes);
    let header_rejected = public_key
        .verify(b"qhs4-attack-message", &wrong_header)
        .is_err();

    accepted
        && wrong_message
        && tampered_rejected
        && wrong_key
        && zero_rejected
        && ff_rejected
        && stateless
        && deterministic
        && header_rejected
}

/// Attacks the QHS-4.1 parallel profile: byte equivalence, tampering, wrong key.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    reason = "the fixed QHS-4 signature is 18,216 bytes"
)]
pub fn attack_qhs41() -> bool {
    let seed = [7_u8; 32];
    let Ok((private_key, public_key)) = qhs4_keygen(&seed) else {
        return false;
    };
    let key_before = private_key.to_bytes();
    let Ok(sequential) = private_key.sign(b"qhs41-attack-message") else {
        return false;
    };
    let Ok(parallel) = qhs4_sign_parallel(&private_key, b"qhs41-attack-message") else {
        return false;
    };
    let key_after = private_key.to_bytes();
    let equivalent = parallel == sequential;
    let accepted = public_key
        .verify(b"qhs41-attack-message", &parallel)
        .is_ok();
    let wrong_message = public_key
        .verify(b"qhs41-wrong-message", &parallel)
        .is_err();
    let stateless = key_before == key_after;
    let tampered_rejected = {
        let mut bytes = parallel.to_bytes();
        if let Some(byte) = bytes.get_mut(100) {
            *byte ^= 1;
        }
        public_key
            .verify(b"qhs41-attack-message", &Qhs4Signature::from_bytes(bytes))
            .is_err()
    };
    let mut wrong_public_bytes = public_key.to_bytes();
    if let Some(byte) = wrong_public_bytes.get_mut(4) {
        *byte ^= 1;
    }
    let wrong_key = Qhs4PublicKey::from_bytes(&wrong_public_bytes)
        .is_ok_and(|other| other.verify(b"qhs41-attack-message", &parallel).is_err());

    equivalent && accepted && wrong_message && stateless && tampered_rejected && wrong_key
}

/// Attacks QHS-4.2 compact: byte equivalence, tampering, wrong key.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    reason = "the fixed QHS-4.2 signature is 14,344 bytes"
)]
pub fn attack_qhs42() -> bool {
    let seed = [7_u8; 32];
    let Ok((private_key, public_key)) = qhs42_keygen(&seed) else {
        return false;
    };
    let key_before = private_key.to_bytes();
    let Ok(sequential) = private_key.sign(b"qhs42-attack-message") else {
        return false;
    };
    let Ok(parallel) = qhs42_sign_parallel(&private_key, b"qhs42-attack-message") else {
        return false;
    };
    let key_after = private_key.to_bytes();
    let equivalent = parallel == sequential;
    let accepted = public_key
        .verify(b"qhs42-attack-message", &parallel)
        .is_ok();
    let wrong_message = public_key
        .verify(b"qhs42-wrong-message", &parallel)
        .is_err();
    let stateless = key_before == key_after;
    let tampered_rejected = {
        let mut bytes = parallel.to_bytes();
        if let Some(byte) = bytes.get_mut(100) {
            *byte ^= 1;
        }
        public_key
            .verify(b"qhs42-attack-message", &Qhs42Signature::from_bytes(bytes))
            .is_err()
    };
    let mut wrong_public_bytes = public_key.to_bytes();
    if let Some(byte) = wrong_public_bytes.get_mut(4) {
        *byte ^= 1;
    }
    let wrong_key = Qhs42PublicKey::from_bytes(&wrong_public_bytes)
        .is_ok_and(|other| other.verify(b"qhs42-attack-message", &parallel).is_err());

    equivalent && accepted && wrong_message && stateless && tampered_rejected && wrong_key
}

/// Attacks QHS-5 with wrong messages, tampering, wrong keys, and exhaustion.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    reason = "the fixed QHS-5 signature is 6,216 bytes"
)]
pub fn attack_qhs5() -> bool {
    let seed = [7_u8; 64];
    let Ok((mut private_key, public_key)) = qhs5_keygen(&seed) else {
        return false;
    };
    let Ok(signature) = private_key.sign(b"qhs5-attack-message") else {
        return false;
    };
    let accepted = public_key
        .verify(b"qhs5-attack-message", &signature)
        .is_ok();
    let wrong_message = public_key
        .verify(b"qhs5-wrong-message", &signature)
        .is_err();
    let counter_advanced = private_key.next_leaf() == 1;

    let tamper_offsets = [0_usize, 1, 2, 3, 4, 5_699, 5_700, 6_211, 6_215];
    let mut tampered_rejected = true;
    for offset in tamper_offsets {
        let mut tampered_bytes = signature.to_bytes();
        if let Some(byte) = tampered_bytes.get_mut(offset) {
            *byte ^= 1;
        }
        let tampered = Qhs5Signature::from_bytes(tampered_bytes);
        if public_key.verify(b"qhs5-attack-message", &tampered).is_ok() {
            tampered_rejected = false;
            break;
        }
    }
    let zero_rejected = public_key
        .verify(
            b"qhs5-attack-message",
            &Qhs5Signature::from_bytes([0_u8; qwp_crypto::QHS5_SIGNATURE_BYTES]),
        )
        .is_err();
    let ff_rejected = public_key
        .verify(
            b"qhs5-attack-message",
            &Qhs5Signature::from_bytes([0xff_u8; qwp_crypto::QHS5_SIGNATURE_BYTES]),
        )
        .is_err();

    let Ok((_, other_public_key)) = qhs5_keygen(&[9_u8; 64]) else {
        return false;
    };
    let wrong_key = other_public_key
        .verify(b"qhs5-attack-message", &signature)
        .is_err();

    let mut key_bytes = private_key.to_bytes();
    if let Some(slot) = key_bytes.get_mut(68..70) {
        slot.copy_from_slice(&QHS5_MAX_SIGNATURES.to_le_bytes());
    }
    let exhausted_ok = Qhs5PrivateKey::from_bytes(&key_bytes)
        .is_ok_and(|mut exhausted| exhausted.sign(b"message") == Err(CryptoError::KeyExhausted));

    accepted
        && wrong_message
        && counter_advanced
        && tampered_rejected
        && wrong_key
        && exhausted_ok
        && zero_rejected
        && ff_rejected
}

/// Attacks QHS-6 with wrong messages, component mixing, tampering, and exhaustion.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    reason = "the fixed QHS-6 signature is 6,284 bytes"
)]
pub fn attack_qhs6() -> bool {
    let qhs5_seed = [7_u8; 64];
    let ed25519_seed = [9_u8; 32];
    let Ok((mut private_key, public_key)) = qhs6_keygen(&qhs5_seed, &ed25519_seed) else {
        return false;
    };
    let Ok(first) = private_key.sign(b"qhs6-attack-first") else {
        return false;
    };
    let Ok(second) = private_key.sign(b"qhs6-attack-second") else {
        return false;
    };
    let accepted = public_key.verify(b"qhs6-attack-first", &first).is_ok();
    let wrong_message = public_key.verify(b"qhs6-attack-wrong", &first).is_err();
    let counter_advanced = private_key.next_leaf() == 2;

    let mixed_ed_rejected = match (
        first.leaf_index(),
        first.qhs5_signature(),
        second.ed25519_signature(),
    ) {
        (Ok(leaf), Ok(qhs5), Ok(ed25519)) => Qhs6Signature::from_parts(leaf, qhs5, ed25519)
            .is_ok_and(|signature| public_key.verify(b"qhs6-attack-first", &signature).is_err()),
        _ => false,
    };

    let mut tampered_qhs5 = first.to_bytes();
    tampered_qhs5[100] ^= 1;
    let qhs5_rejected = Qhs6Signature::from_slice(&tampered_qhs5)
        .is_ok_and(|signature| public_key.verify(b"qhs6-attack-first", &signature).is_err());
    let mut tampered_ed = first.to_bytes();
    tampered_ed[6_250] ^= 1;
    let ed_rejected = Qhs6Signature::from_slice(&tampered_ed)
        .is_ok_and(|signature| public_key.verify(b"qhs6-attack-first", &signature).is_err());

    let zero_rejected = Qhs6Signature::from_slice(&[0_u8; QHS6_SIGNATURE_BYTES]).is_err();
    let cross_version = Qhs5Signature::from_slice(&first.to_bytes()).is_err();

    let Ok((_, other_public)) = qhs6_keygen(&[11_u8; 64], &[12_u8; 32]) else {
        return false;
    };
    let wrong_key = other_public.verify(b"qhs6-attack-first", &first).is_err();

    let mut key_bytes = private_key.to_bytes();
    if let Some(slot) = key_bytes.get_mut(72..74) {
        slot.copy_from_slice(&QHS5_MAX_SIGNATURES.to_le_bytes());
    }
    let exhausted_ok = Qhs6PrivateKey::from_bytes(&key_bytes)
        .is_ok_and(|mut exhausted| exhausted.sign(b"message") == Err(CryptoError::KeyExhausted));

    accepted
        && wrong_message
        && counter_advanced
        && mixed_ed_rejected
        && qhs5_rejected
        && ed_rejected
        && zero_rejected
        && cross_version
        && wrong_key
        && exhausted_ok
}

/// Attacks the QHS-E verifier profile against QHS-1/2/3/3.1.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    reason = "the fixed QHS-1/2/3 signatures are 1.7-2.4 KB"
)]
pub fn attack_qhse() -> bool {
    let seed = [7_u8; 32];
    let message = b"qhse-attack-message";

    let Ok((mut private1, public1)) = qhs_keygen(&seed) else {
        return false;
    };
    let Ok(signature1) = private1.sign(message) else {
        return false;
    };
    let public1 = public1.to_bytes();
    let signature1 = signature1.to_bytes();
    let accepted1 = verify_qhs1(&public1, message, &signature1).is_ok();
    let wrong1 = verify_qhs1(&public1, b"wrong", &signature1).is_err();
    let tamper1 = [0_usize, 1, 2, 3, 4, 2_147, 2_148, 2_403, 2_404]
        .iter()
        .all(|offset| {
            let mut bytes = signature1;
            let Some(byte) = bytes.get_mut(*offset) else {
                return false;
            };
            *byte ^= 1;
            verify_qhs1(&public1, message, &bytes).is_err()
        });
    let zero1 = verify_qhs1(&public1, message, &[0_u8; 2_408]).is_err();

    let Ok((mut private2, public2)) = qhs2_keygen(&seed) else {
        return false;
    };
    let Ok(signature2) = private2.sign(message) else {
        return false;
    };
    let public2 = public2.to_bytes();
    let signature2 = signature2.to_bytes();
    let accepted2 = verify_qhs2(&public2, message, &signature2).is_ok();
    let wrong2 = verify_qhs2(&public2, b"wrong", &signature2).is_err();
    let tamper2 = [0_usize, 1, 2, 3, 4, 1_443, 1_444, 1_699, 1_700]
        .iter()
        .all(|offset| {
            let mut bytes = signature2;
            let Some(byte) = bytes.get_mut(*offset) else {
                return false;
            };
            *byte ^= 1;
            verify_qhs2(&public2, message, &bytes).is_err()
        });
    let zero2 = verify_qhs2(&public2, message, &[0_u8; 1_704]).is_err();

    let Ok((mut private3, public3)) = qhs3_keygen(&seed) else {
        return false;
    };
    let Ok(signature3) = private3.sign(message) else {
        return false;
    };
    let public3 = public3.to_bytes();
    let signature3 = signature3.to_bytes();
    let accepted3 = verify_qhs3(&public3, message, &signature3).is_ok()
        && verify_qhs31(&public3, message, &signature3).is_ok();
    let wrong3 = verify_qhs3(&public3, b"wrong", &signature3).is_err();
    let tamper3 = [0_usize, 1, 2, 3, 4, 1_443, 1_444, 1_827, 1_828]
        .iter()
        .all(|offset| {
            let mut bytes = signature3;
            let Some(byte) = bytes.get_mut(*offset) else {
                return false;
            };
            *byte ^= 1;
            verify_qhs3(&public3, message, &bytes).is_err()
        });
    let zero3 = verify_qhs3(&public3, message, &[0_u8; 1_832]).is_err();

    accepted1
        && wrong1
        && tamper1
        && zero1
        && accepted2
        && wrong2
        && tamper2
        && zero2
        && accepted3
        && wrong3
        && tamper3
        && zero3
}

#[cfg(test)]
mod tests {
    use super::{
        attack_braid_parser, attack_entropy, attack_hash_vectors, attack_key_formats,
        attack_polynomial_round_trip, attack_qhs1, attack_qhs2, attack_qhs3, attack_qhs4,
        attack_qhs5, attack_qhs6, attack_qhs41, attack_qhs42, attack_qhse, audit, run_all,
    };

    #[test]
    fn attacks_pass() {
        assert!(attack_braid_parser());
        assert!(attack_polynomial_round_trip());
        assert!(attack_key_formats());
        assert!(attack_hash_vectors());
        assert!(attack_entropy());
        assert!(attack_qhs1());
        assert!(attack_qhs2());
        assert!(attack_qhs3());
        assert!(attack_qhs4());
        assert!(attack_qhs41());
        assert!(attack_qhs42());
        assert!(attack_qhs5());
        assert!(attack_qhs6());
        assert!(attack_qhse());
        assert!(run_all().is_ok());
    }

    #[test]
    fn audit_artifacts_exist() {
        assert!(audit().unwrap().is_ok());
    }
}
