//! Verifier-only QHS-1/2/3/3.1 profile.

use qwp_core::CryptoError;
use qwp_hash::{Hasher, derive_key32};

/// QHS-E public-key size (same for QHS-1/2/3/3.1).
pub const QHS_E_PUBLIC_KEY_BYTES: usize = 64;
/// QHS-1 signature size.
pub const QHS_E_QHS1_SIGNATURE_BYTES: usize = 2_408;
/// QHS-2 signature size.
pub const QHS_E_QHS2_SIGNATURE_BYTES: usize = 1_704;
/// QHS-3 / QHS-3.1 signature size.
pub const QHS_E_QHS3_SIGNATURE_BYTES: usize = 1_832;

const MAX_CHAINS: usize = 67;

#[derive(Clone, Copy)]
enum Digits {
    Hex,
    Base64,
}

struct Params {
    version: u8,
    height: u8,
    chains: usize,
    chain_len: u8,
    tree_height: usize,
    max_signatures: u16,
    signature_bytes: usize,
    wots_offset: usize,
    auth_offset: usize,
    checksum_offset: usize,
    digits: Digits,
    message_context: &'static [u8],
    chain_context: &'static [u8],
    wots_pk_context: &'static [u8],
    leaf_context: &'static [u8],
    node_context: &'static [u8],
    checksum_context: &'static [u8],
}

const QHS1: Params = Params {
    version: 1,
    height: 8,
    chains: 67,
    chain_len: 15,
    tree_height: 8,
    max_signatures: 256,
    signature_bytes: QHS_E_QHS1_SIGNATURE_BYTES,
    wots_offset: 4,
    auth_offset: 2_148,
    checksum_offset: 2_404,
    digits: Digits::Hex,
    message_context: b"qWp QHS-1 message",
    chain_context: b"qWp QHS-1 chain",
    wots_pk_context: b"qWp QHS-1 wots-pk",
    leaf_context: b"qWp QHS-1 leaf",
    node_context: b"qWp QHS-1 node",
    checksum_context: b"qWp QHS-1 signature-checksum",
};

const QHS2: Params = Params {
    version: 2,
    height: 8,
    chains: 45,
    chain_len: 63,
    tree_height: 8,
    max_signatures: 256,
    signature_bytes: QHS_E_QHS2_SIGNATURE_BYTES,
    wots_offset: 4,
    auth_offset: 1_444,
    checksum_offset: 1_700,
    digits: Digits::Base64,
    message_context: b"qWp QHS-2 message",
    chain_context: b"qWp QHS-2 chain",
    wots_pk_context: b"qWp QHS-2 wots-pk",
    leaf_context: b"qWp QHS-2 leaf",
    node_context: b"qWp QHS-2 node",
    checksum_context: b"qWp QHS-2 signature-checksum",
};

const QHS3: Params = Params {
    version: 3,
    height: 12,
    chains: 45,
    chain_len: 63,
    tree_height: 12,
    max_signatures: 4_096,
    signature_bytes: QHS_E_QHS3_SIGNATURE_BYTES,
    wots_offset: 4,
    auth_offset: 1_444,
    checksum_offset: 1_828,
    digits: Digits::Base64,
    message_context: b"qWp QHS-3 message",
    chain_context: b"qWp QHS-3 chain",
    wots_pk_context: b"qWp QHS-3 wots-pk",
    leaf_context: b"qWp QHS-3 leaf",
    node_context: b"qWp QHS-3 node",
    checksum_context: b"qWp QHS-3 signature-checksum",
};

/// Verifies a QHS-1 signature.
///
/// # Errors
///
/// Returns [`CryptoError::VerificationFailed`] for an invalid signature and
/// [`CryptoError::InvalidLength`] for a malformed fixed-layout key/header.
#[inline]
pub fn verify_qhs1(
    public_key: &[u8; QHS_E_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; QHS_E_QHS1_SIGNATURE_BYTES],
) -> Result<(), CryptoError> {
    verify_common(public_key, message, signature, &QHS1)
}

/// Verifies a QHS-2 signature.
///
/// # Errors
///
/// Returns [`CryptoError::VerificationFailed`] for an invalid signature and
/// [`CryptoError::InvalidLength`] for a malformed fixed-layout key/header.
#[inline]
pub fn verify_qhs2(
    public_key: &[u8; QHS_E_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; QHS_E_QHS2_SIGNATURE_BYTES],
) -> Result<(), CryptoError> {
    verify_common(public_key, message, signature, &QHS2)
}

/// Verifies a QHS-3 signature.
///
/// # Errors
///
/// Returns [`CryptoError::VerificationFailed`] for an invalid signature and
/// [`CryptoError::InvalidLength`] for a malformed fixed-layout key/header.
#[inline]
pub fn verify_qhs3(
    public_key: &[u8; QHS_E_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; QHS_E_QHS3_SIGNATURE_BYTES],
) -> Result<(), CryptoError> {
    verify_common(public_key, message, signature, &QHS3)
}

/// Verifies a QHS-3.1 signature (same format as QHS-3).
///
/// # Errors
///
/// Returns [`CryptoError::VerificationFailed`] for an invalid signature and
/// [`CryptoError::InvalidLength`] for a malformed fixed-layout key/header.
#[inline]
pub fn verify_qhs31(
    public_key: &[u8; QHS_E_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; QHS_E_QHS3_SIGNATURE_BYTES],
) -> Result<(), CryptoError> {
    verify_qhs3(public_key, message, signature)
}

fn verify_common(
    public_key: &[u8; QHS_E_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8],
    params: &Params,
) -> Result<(), CryptoError> {
    if signature.len() != params.signature_bytes {
        return Err(CryptoError::InvalidLength);
    }
    let key_header = public_key.get(..4).ok_or(CryptoError::InvalidLength)?;
    if key_header != [params.version, params.version, params.height, 0] {
        return Err(CryptoError::InvalidLength);
    }
    let key_tail = public_key.get(36..).ok_or(CryptoError::InvalidLength)?;
    if key_tail.iter().any(|byte| *byte != 0) {
        return Err(CryptoError::InvalidLength);
    }
    if signature.get(..2) != Some([params.version, params.version].as_slice()) {
        return Err(CryptoError::VerificationFailed);
    }
    let leaf_bytes = signature.get(2..4).ok_or(CryptoError::VerificationFailed)?;
    let mut leaf_word = [0_u8; 2];
    leaf_word.copy_from_slice(leaf_bytes);
    let leaf_index = u16::from_le_bytes(leaf_word);
    if leaf_index >= params.max_signatures {
        return Err(CryptoError::VerificationFailed);
    }

    let body = signature
        .get(..params.checksum_offset)
        .ok_or(CryptoError::VerificationFailed)?;
    let expected_checksum = signature_checksum(params, body)?;
    let actual_checksum = signature
        .get(params.checksum_offset..)
        .ok_or(CryptoError::VerificationFailed)?;
    if actual_checksum != expected_checksum {
        return Err(CryptoError::VerificationFailed);
    }

    let digits = message_digits(params, message);
    let wots_signature = signature
        .get(params.wots_offset..params.auth_offset)
        .ok_or(CryptoError::VerificationFailed)?;
    let wots_digits = digits
        .get(..params.chains)
        .ok_or(CryptoError::InvalidLength)?;
    let wots_pk = wots_verify(params, wots_signature, wots_digits)?;
    let mut node = leaf_hash(params, leaf_index, &wots_pk);
    let auth_path = signature
        .get(params.auth_offset..params.checksum_offset)
        .ok_or(CryptoError::VerificationFailed)?;

    for level in 0..params.tree_height {
        let start = level.saturating_mul(32);
        let end = start.saturating_add(32);
        let sibling = auth_path
            .get(start..end)
            .ok_or(CryptoError::VerificationFailed)?;
        let sibling_array =
            <[u8; 32]>::try_from(sibling).map_err(|_| CryptoError::InvalidLength)?;
        let level_u32 = u32::try_from(level).unwrap_or(0);
        let bit = leaf_index.checked_shr(level_u32).unwrap_or(0) & 1;
        node = if bit == 0 {
            node_hash(params, &node, &sibling_array)
        } else {
            node_hash(params, &sibling_array, &node)
        };
    }

    let root = public_key.get(4..36).ok_or(CryptoError::InvalidLength)?;
    if node == root {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

fn message_digits(params: &Params, message: &[u8]) -> [u8; MAX_CHAINS] {
    let digest = derive_key32(params.message_context, message).to_bytes();
    let mut digits = [0_u8; MAX_CHAINS];
    match params.digits {
        Digits::Hex => {
            for (index, byte) in digest.iter().enumerate() {
                let high = index.saturating_mul(2);
                let low = high.saturating_add(1);
                if let Some(slot) = digits.get_mut(high) {
                    *slot = byte.wrapping_shr(4);
                }
                if let Some(slot) = digits.get_mut(low) {
                    *slot = byte & 0x0f;
                }
            }
            let mut checksum = 0_u16;
            for digit in digits.iter().take(64) {
                checksum = checksum.wrapping_add(15_u16.saturating_sub(u16::from(*digit)));
            }
            if let Some(slot) = digits.get_mut(64) {
                *slot = u8::try_from(checksum.wrapping_shr(8) & 0x0f).unwrap_or(0);
            }
            if let Some(slot) = digits.get_mut(65) {
                *slot = u8::try_from(checksum.wrapping_shr(4) & 0x0f).unwrap_or(0);
            }
            if let Some(slot) = digits.get_mut(66) {
                *slot = u8::try_from(checksum & 0x0f).unwrap_or(0);
            }
        }
        Digits::Base64 => {
            for index in 0..43_usize {
                let mut value = 0_u8;
                for offset in 0..6 {
                    let padded_bit = index.saturating_mul(6).saturating_add(offset);
                    let bit = if padded_bit < 2 {
                        0
                    } else {
                        let digest_bit = padded_bit.saturating_sub(2);
                        let byte_index = digest_bit.checked_div(8).unwrap_or(0);
                        let shift =
                            7_u32.saturating_sub(u32::try_from(digest_bit % 8).unwrap_or(0));
                        digest
                            .get(byte_index)
                            .map_or(0, |byte| byte.wrapping_shr(shift) & 1)
                    };
                    value = value.wrapping_shl(1) | bit;
                }
                if let Some(slot) = digits.get_mut(index) {
                    *slot = value;
                }
            }
            let mut checksum = 0_u16;
            for digit in digits.iter().take(43) {
                checksum = checksum.wrapping_add(63_u16.saturating_sub(u16::from(*digit)));
            }
            if let Some(slot) = digits.get_mut(43) {
                *slot = u8::try_from(checksum.wrapping_shr(6)).unwrap_or(0);
            }
            if let Some(slot) = digits.get_mut(44) {
                *slot = u8::try_from(checksum & 0x3f).unwrap_or(0);
            }
        }
    }
    digits
}

fn wots_verify(params: &Params, signature: &[u8], digits: &[u8]) -> Result<[u8; 32], CryptoError> {
    let chunks = signature.as_chunks::<32>().0;
    if chunks.len() != params.chains || digits.len() != params.chains {
        return Err(CryptoError::InvalidLength);
    }
    let mut hasher = Hasher::new_derive_key(params.wots_pk_context);
    for (chunk, digit) in chunks.iter().zip(digits.iter()) {
        let mut value = [0_u8; 32];
        value.copy_from_slice(chunk);
        let steps = params.chain_len.saturating_sub(*digit);
        for _ in 0..steps {
            value = derive_key32(params.chain_context, &value).to_bytes();
        }
        hasher.update(&value);
    }
    Ok(hasher.finalize().to_bytes())
}

fn leaf_hash(params: &Params, leaf_index: u16, wots_pk: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 34];
    if let Some(slot) = input.get_mut(0..2) {
        slot.copy_from_slice(&leaf_index.to_le_bytes());
    }
    if let Some(slot) = input.get_mut(2..34) {
        slot.copy_from_slice(wots_pk);
    }
    derive_key32(params.leaf_context, &input).to_bytes()
}

fn node_hash(params: &Params, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 64];
    if let Some(slot) = input.get_mut(0..32) {
        slot.copy_from_slice(left);
    }
    if let Some(slot) = input.get_mut(32..64) {
        slot.copy_from_slice(right);
    }
    derive_key32(params.node_context, &input).to_bytes()
}

fn signature_checksum(params: &Params, body: &[u8]) -> Result<[u8; 4], CryptoError> {
    let hash = derive_key32(params.checksum_context, body);
    let mut checksum = [0_u8; 4];
    let source = hash.as_bytes().get(..4).ok_or(CryptoError::InvalidLength)?;
    checksum.copy_from_slice(source);
    Ok(checksum)
}

#[cfg(test)]
mod tests {
    use super::{QHS1, wots_verify};

    #[test]
    fn wots_verify_rejects_wrong_lengths() {
        let signature = [0_u8; 67 * 32];
        assert!(wots_verify(&QHS1, &signature, &[]).is_err());
        assert!(wots_verify(&QHS1, &signature[..1], &[0_u8; 67]).is_err());
    }
}
