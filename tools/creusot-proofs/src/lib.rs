//! Creusot contracts for the QHS-E digit, checksum, and Merkle bounds.
//!
//! These functions mirror the arithmetic in `crates/qwp-e/src/verifier.rs`.
//! They are a proof model, not a second production implementation. The goal is
//! to prove that the index and digit arithmetic cannot overflow or leave the
//! fixed arrays for any input accepted by the public QHS-E API.

use creusot_std::prelude::*;

/// Extracts one 6-bit base-64 digit.
///
/// The first two padded bits are zero, matching the QHS-2/3/3.1 encoding.
#[requires(index@ < 43)]
#[ensures(result@ < 64)]
pub fn base64_digit(index: usize, digest: &[u8; 32]) -> u8 {
    let mut value = 0_u8;
    let mut offset = 0_usize;
    #[invariant(offset@ <= 6)]
    #[invariant(value@ < 64)]
    while offset < 6 {
        let padded_bit = index * 6 + offset;
        let bit = if padded_bit < 2 {
            0
        } else {
            let digest_bit = padded_bit - 2;
            proof_assert!(digest_bit@ < 256);
            let byte_index = digest_bit / 8;
            proof_assert!(byte_index@ < 32);
            let shift = 7 - (digest_bit % 8);
            (digest[byte_index] >> shift) & 1
        };
        value = ((value << 1) | bit) % 64;
        offset += 1;
    }
    value
}

/// Extracts one hexadecimal digit (QHS-1 encoding).
#[requires(index@ < 64)]
#[ensures(result@ < 16)]
pub fn hex_digit(index: usize, digest: &[u8; 32]) -> u8 {
    proof_assert!(index@ / 2 < 32);
    let byte = digest[index / 2];
    proof_assert!(byte@ <= 255);
    if index % 2 == 0 {
        byte / 16
    } else {
        byte % 16
    }
}

/// Computes the QHS-1 three-nibble checksum sum.
#[requires(digits@.len() == 64)]
#[requires(forall<i: Int> 0 <= i && i < 64 ==> digits@[i]@ <= 15)]
#[ensures(result@ <= 960)]
pub fn hex_checksum(digits: &[u8; 64]) -> u16 {
    let mut sum = 0_u16;
    let mut index = 0_usize;
    #[invariant(index@ <= 64)]
    #[invariant(sum@ <= 15 * index@)]
    while index < 64 {
        sum += 15 - u16::from(digits[index]);
        index += 1;
    }
    sum
}

/// Computes the QHS-2/3 two-digit checksum sum.
#[requires(digits@.len() == 43)]
#[requires(forall<i: Int> 0 <= i && i < 43 ==> digits@[i]@ <= 63)]
#[ensures(result@ <= 2709)]
pub fn base64_checksum(digits: &[u8; 43]) -> u16 {
    let mut sum = 0_u16;
    let mut index = 0_usize;
    #[invariant(index@ <= 43)]
    #[invariant(sum@ <= 63 * index@)]
    while index < 43 {
        sum += 63 - u16::from(digits[index]);
        index += 1;
    }
    sum
}

/// Computes a Merkle auth-path offset.
#[requires(level@ < 12)]
#[ensures(result@ < 384)]
pub fn auth_path_offset(level: usize) -> usize {
    level * 32
}

/// QHS-1/2 leaf-index bound.
#[ensures(result == (index@ < 256))]
pub fn qhs12_leaf_valid(index: u16) -> bool {
    index < 256
}

/// QHS-3/3.1 leaf-index bound.
#[ensures(result == (index@ < 4096))]
pub fn qhs3_leaf_valid(index: u16) -> bool {
    index < 4096
}
