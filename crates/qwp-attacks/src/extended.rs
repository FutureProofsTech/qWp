//! Extended adversarial checks: structural tampering with repaired checksums,
//! message boundaries, public-key mutations, cross-version confusion, QHS-6
//! component binding, and Ed25519 edge cases.

#![allow(
    clippy::similar_names,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "version-suffixed attack variables and fixed signature offsets are intentional"
)]

use qwp_classical::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use qwp_crypto::{
    Qhs2PublicKey, Qhs2Signature, Qhs3PublicKey, Qhs3Signature, Qhs4PublicKey, Qhs4Signature,
    Qhs5PublicKey, Qhs5Signature, Qhs6PublicKey, Qhs6Signature, Qhs42PublicKey, Qhs42Signature,
    QhsPublicKey, QhsSignature, qhs_keygen, qhs2_keygen, qhs3_keygen, qhs4_keygen, qhs5_keygen,
    qhs6_keygen, qhs42_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3, verify_qhs31};
use qwp_hash::{derive_key32, derive_key64};

const SEED: [u8; 32] = [7_u8; 32];
const SEED64: [u8; 64] = [7_u8; 64];
const MESSAGE: &[u8] = b"qwp-extended-attack-message";

fn checksum32(context: &[u8], body: &[u8]) -> [u8; 4] {
    let hash = derive_key32(context, body).to_bytes();
    let mut output = [0_u8; 4];
    output.copy_from_slice(&hash[..4]);
    output
}

fn checksum64(context: &[u8], body: &[u8]) -> [u8; 4] {
    let hash = derive_key64(context, body).to_bytes();
    let mut output = [0_u8; 4];
    output.copy_from_slice(&hash[..4]);
    output
}

fn repair32(signature: &mut [u8], body_len: usize, checksum_offset: usize, context: &[u8]) -> bool {
    let Some(body) = signature.get(..body_len) else {
        return false;
    };
    let sum = checksum32(context, body);
    let Some(slot) = signature.get_mut(checksum_offset..checksum_offset.saturating_add(4)) else {
        return false;
    };
    slot.copy_from_slice(&sum);
    true
}

fn repair64(signature: &mut [u8], body_len: usize, checksum_offset: usize, context: &[u8]) -> bool {
    let Some(body) = signature.get(..body_len) else {
        return false;
    };
    let sum = checksum64(context, body);
    let Some(slot) = signature.get_mut(checksum_offset..checksum_offset.saturating_add(4)) else {
        return false;
    };
    slot.copy_from_slice(&sum);
    true
}

fn set_leaf(signature: &mut [u8], leaf: u16) -> bool {
    let Some(slot) = signature.get_mut(2..4) else {
        return false;
    };
    slot.copy_from_slice(&leaf.to_le_bytes());
    true
}

fn transplant(signature: &mut [u8], source: usize, destination: usize, len: usize) -> bool {
    let Some(chunk) = signature.get(source..source.saturating_add(len)) else {
        return false;
    };
    let mut copy = vec![0_u8; len];
    copy.copy_from_slice(chunk);
    let Some(slot) = signature.get_mut(destination..destination.saturating_add(len)) else {
        return false;
    };
    slot.copy_from_slice(&copy);
    true
}

/// Structural tampering with a recomputed format checksum.
///
/// A byte flip is often rejected by the unkeyed checksum. A real attacker can
/// recompute that checksum, so this attack changes a leaf index, WOTS chunk,
/// Merkle auth path, FORS entry, or hypertree layer and repairs the checksum.
/// Every case must still be rejected by the cryptographic verification.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::too_many_lines,
    reason = "the fixed QHS-4/4.2 signatures are 14-18 KB and each version has a fixed layout"
)]
pub fn attack_structural_checksums() -> bool {
    let mut ok = true;

    // QHS-1: 67 chains x 32, auth offset 2148, checksum 2404.
    {
        let Ok((mut private, public)) = qhs_keygen(&SEED) else {
            return false;
        };
        let Ok(signature) = private.sign(MESSAGE) else {
            return false;
        };
        let base = signature.to_bytes();
        let context = b"qWp QHS-1 signature-checksum";
        for leaf in [1_u16, 2, 255, 256, u16::MAX] {
            let mut bytes = base;
            ok &= set_leaf(&mut bytes, leaf);
            ok &= repair32(&mut bytes, 2_404, 2_404, context);
            ok &= public
                .verify(MESSAGE, &QhsSignature::from_bytes(bytes))
                .is_err();
            ok &= verify_qhs1(&public.to_bytes(), MESSAGE, &bytes).is_err();
        }
        for chain in [0_usize, 1, 33, 66] {
            let mut bytes = base;
            let offset = 4_usize.saturating_add(chain.saturating_mul(32));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 2_404, 2_404, context);
            ok &= public
                .verify(MESSAGE, &QhsSignature::from_bytes(bytes))
                .is_err();
        }
        for level in [0_usize, 4, 7] {
            let mut bytes = base;
            let offset = 2_148_usize.saturating_add(level.saturating_mul(32));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 2_404, 2_404, context);
            ok &= public
                .verify(MESSAGE, &QhsSignature::from_bytes(bytes))
                .is_err();
        }
        let mut bytes = base;
        ok &= transplant(&mut bytes, 4, 36, 32);
        ok &= repair32(&mut bytes, 2_404, 2_404, context);
        ok &= public
            .verify(MESSAGE, &QhsSignature::from_bytes(bytes))
            .is_err();
        let mut bytes = base;
        ok &= transplant(&mut bytes, 2_148, 2_180, 32);
        ok &= repair32(&mut bytes, 2_404, 2_404, context);
        ok &= public
            .verify(MESSAGE, &QhsSignature::from_bytes(bytes))
            .is_err();
    }

    // QHS-2: 45 chains x 32, auth offset 1444, checksum 1700.
    {
        let Ok((mut private, public)) = qhs2_keygen(&SEED) else {
            return false;
        };
        let Ok(signature) = private.sign(MESSAGE) else {
            return false;
        };
        let base = signature.to_bytes();
        let context = b"qWp QHS-2 signature-checksum";
        for leaf in [1_u16, 2, 255, 256, u16::MAX] {
            let mut bytes = base;
            ok &= set_leaf(&mut bytes, leaf);
            ok &= repair32(&mut bytes, 1_700, 1_700, context);
            ok &= public
                .verify(MESSAGE, &Qhs2Signature::from_bytes(bytes))
                .is_err();
            ok &= verify_qhs2(&public.to_bytes(), MESSAGE, &bytes).is_err();
        }
        for chain in [0_usize, 1, 22, 44] {
            let mut bytes = base;
            let offset = 4_usize.saturating_add(chain.saturating_mul(32));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 1_700, 1_700, context);
            ok &= public
                .verify(MESSAGE, &Qhs2Signature::from_bytes(bytes))
                .is_err();
        }
        for level in [0_usize, 4, 7] {
            let mut bytes = base;
            let offset = 1_444_usize.saturating_add(level.saturating_mul(32));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 1_700, 1_700, context);
            ok &= public
                .verify(MESSAGE, &Qhs2Signature::from_bytes(bytes))
                .is_err();
        }
        let mut bytes = base;
        ok &= transplant(&mut bytes, 4, 36, 32);
        ok &= repair32(&mut bytes, 1_700, 1_700, context);
        ok &= public
            .verify(MESSAGE, &Qhs2Signature::from_bytes(bytes))
            .is_err();
        let mut bytes = base;
        ok &= transplant(&mut bytes, 1_444, 1_476, 32);
        ok &= repair32(&mut bytes, 1_700, 1_700, context);
        ok &= public
            .verify(MESSAGE, &Qhs2Signature::from_bytes(bytes))
            .is_err();
    }

    // QHS-3: 45 chains x 32, auth offset 1444, checksum 1828, 12 levels.
    {
        let Ok((mut private, public)) = qhs3_keygen(&SEED) else {
            return false;
        };
        let Ok(signature) = private.sign(MESSAGE) else {
            return false;
        };
        let base = signature.to_bytes();
        let context = b"qWp QHS-3 signature-checksum";
        for leaf in [1_u16, 2, 4_095, 4_096, u16::MAX] {
            let mut bytes = base;
            ok &= set_leaf(&mut bytes, leaf);
            ok &= repair32(&mut bytes, 1_828, 1_828, context);
            ok &= public
                .verify(MESSAGE, &Qhs3Signature::from_bytes(bytes))
                .is_err();
            ok &= verify_qhs3(&public.to_bytes(), MESSAGE, &bytes).is_err();
            ok &= verify_qhs31(&public.to_bytes(), MESSAGE, &bytes).is_err();
        }
        for chain in [0_usize, 1, 22, 44] {
            let mut bytes = base;
            let offset = 4_usize.saturating_add(chain.saturating_mul(32));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 1_828, 1_828, context);
            ok &= public
                .verify(MESSAGE, &Qhs3Signature::from_bytes(bytes))
                .is_err();
        }
        for level in [0_usize, 6, 11] {
            let mut bytes = base;
            let offset = 1_444_usize.saturating_add(level.saturating_mul(32));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 1_828, 1_828, context);
            ok &= public
                .verify(MESSAGE, &Qhs3Signature::from_bytes(bytes))
                .is_err();
        }
        let mut bytes = base;
        ok &= transplant(&mut bytes, 4, 36, 32);
        ok &= repair32(&mut bytes, 1_828, 1_828, context);
        ok &= public
            .verify(MESSAGE, &Qhs3Signature::from_bytes(bytes))
            .is_err();
        let mut bytes = base;
        ok &= transplant(&mut bytes, 1_444, 1_476, 32);
        ok &= repair32(&mut bytes, 1_828, 1_828, context);
        ok &= public
            .verify(MESSAGE, &Qhs3Signature::from_bytes(bytes))
            .is_err();
    }

    // QHS-4: FORS offset 36, layer offset 4644, checksum 18212.
    {
        let Ok((private, public)) = qhs4_keygen(&SEED) else {
            return false;
        };
        let Ok(signature) = private.sign(MESSAGE) else {
            return false;
        };
        let base = signature.to_bytes();
        let context = b"qWp QHS-4 signature-checksum";
        for offset in [
            0_usize,
            1,
            2,
            3,
            4,
            36,
            68,
            4_644,
            6_084,
            4_644 + 7 * 1_696,
            18_211,
        ] {
            let mut bytes = base;
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 18_212, 18_212, context);
            ok &= public
                .verify(MESSAGE, &Qhs4Signature::from_bytes(bytes))
                .is_err();
        }
        let mut bytes = base;
        ok &= transplant(&mut bytes, 36, 324, 288);
        ok &= repair32(&mut bytes, 18_212, 18_212, context);
        ok &= public
            .verify(MESSAGE, &Qhs4Signature::from_bytes(bytes))
            .is_err();
        let mut bytes = base;
        ok &= transplant(&mut bytes, 4_644, 6_340, 1_696);
        ok &= repair32(&mut bytes, 18_212, 18_212, context);
        ok &= public
            .verify(MESSAGE, &Qhs4Signature::from_bytes(bytes))
            .is_err();
    }

    // QHS-4.2: FORS offset 36, layer offset 4932, checksum 14340.
    {
        let Ok((private, public)) = qhs42_keygen(&SEED) else {
            return false;
        };
        let Ok(signature) = private.sign(MESSAGE) else {
            return false;
        };
        let base = signature.to_bytes();
        let context = b"qWp QHS-4.2 signature-checksum";
        for offset in [
            0_usize,
            1,
            2,
            3,
            4,
            36,
            68,
            4_932,
            6_020,
            4_932 + 6 * 1_344,
            14_339,
        ] {
            let mut bytes = base;
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair32(&mut bytes, 14_340, 14_340, context);
            ok &= public
                .verify(MESSAGE, &Qhs42Signature::from_bytes(bytes))
                .is_err();
        }
        let mut bytes = base;
        ok &= transplant(&mut bytes, 36, 324, 288);
        ok &= repair32(&mut bytes, 14_340, 14_340, context);
        ok &= public
            .verify(MESSAGE, &Qhs42Signature::from_bytes(bytes))
            .is_err();
        let mut bytes = base;
        ok &= transplant(&mut bytes, 4_932, 6_276, 1_344);
        ok &= repair32(&mut bytes, 14_340, 14_340, context);
        ok &= public
            .verify(MESSAGE, &Qhs42Signature::from_bytes(bytes))
            .is_err();
    }

    // QHS-5: 89 chains x 64, auth offset 5700, checksum 6212.
    {
        let Ok((mut private, public)) = qhs5_keygen(&SEED64) else {
            return false;
        };
        let Ok(signature) = private.sign(MESSAGE) else {
            return false;
        };
        let base = signature.to_bytes();
        let context = b"qWp QHS-5 signature-checksum";
        for leaf in [1_u16, 2, 255, 256, u16::MAX] {
            let mut bytes = base;
            ok &= set_leaf(&mut bytes, leaf);
            ok &= repair64(&mut bytes, 6_212, 6_212, context);
            ok &= public
                .verify(MESSAGE, &Qhs5Signature::from_bytes(bytes))
                .is_err();
        }
        for chain in [0_usize, 1, 44, 88] {
            let mut bytes = base;
            let offset = 4_usize.saturating_add(chain.saturating_mul(64));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair64(&mut bytes, 6_212, 6_212, context);
            ok &= public
                .verify(MESSAGE, &Qhs5Signature::from_bytes(bytes))
                .is_err();
        }
        for level in [0_usize, 4, 7] {
            let mut bytes = base;
            let offset = 5_700_usize.saturating_add(level.saturating_mul(64));
            if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= repair64(&mut bytes, 6_212, 6_212, context);
            ok &= public
                .verify(MESSAGE, &Qhs5Signature::from_bytes(bytes))
                .is_err();
        }
        let mut bytes = base;
        ok &= transplant(&mut bytes, 4, 68, 64);
        ok &= repair64(&mut bytes, 6_212, 6_212, context);
        ok &= public
            .verify(MESSAGE, &Qhs5Signature::from_bytes(bytes))
            .is_err();
        let mut bytes = base;
        ok &= transplant(&mut bytes, 5_700, 5_764, 64);
        ok &= repair64(&mut bytes, 6_212, 6_212, context);
        ok &= public
            .verify(MESSAGE, &Qhs5Signature::from_bytes(bytes))
            .is_err();
    }

    // QHS-6: embedded QHS-5 signature at 4, Ed25519 at 6220.
    {
        let Ok((mut private, public)) = qhs6_keygen(&SEED64, &SEED) else {
            return false;
        };
        let Ok(signature) = private.sign(MESSAGE) else {
            return false;
        };
        let base = signature.to_bytes();
        let context = b"qWp QHS-5 signature-checksum";
        for leaf in [1_u16, 2, 255, 256, u16::MAX] {
            let mut bytes = base;
            let Some(mut qhs5) = bytes
                .get(4..6_220)
                .and_then(|source| <[u8; 6_216]>::try_from(source).ok())
            else {
                return false;
            };
            let Some(slot) = bytes.get_mut(6..8) else {
                return false;
            };
            slot.copy_from_slice(&leaf.to_le_bytes());
            let Some(slot) = qhs5.get_mut(2..4) else {
                return false;
            };
            slot.copy_from_slice(&leaf.to_le_bytes());
            ok &= repair64(&mut qhs5, 6_212, 6_212, context);
            let Some(slot) = bytes.get_mut(4..6_220) else {
                return false;
            };
            slot.copy_from_slice(&qhs5);
            ok &= !Qhs6Signature::from_slice(&bytes)
                .is_ok_and(|parsed| public.verify(MESSAGE, &parsed).is_ok());
        }
        for offset in [8_usize, 104, 5_704, 6_215, 6_220, 6_250, 6_283] {
            let mut bytes = base;
            if offset < 6_220 {
                let Some(mut qhs5) = bytes
                    .get(4..6_220)
                    .and_then(|source| <[u8; 6_216]>::try_from(source).ok())
                else {
                    return false;
                };
                let relative = offset.saturating_sub(4);
                if let Some(byte) = qhs5.get_mut(relative) {
                    *byte ^= 1;
                }
                ok &= repair64(&mut qhs5, 6_212, 6_212, context);
                let Some(slot) = bytes.get_mut(4..6_220) else {
                    return false;
                };
                slot.copy_from_slice(&qhs5);
            } else if let Some(byte) = bytes.get_mut(offset) {
                *byte ^= 1;
            }
            ok &= !Qhs6Signature::from_slice(&bytes)
                .is_ok_and(|parsed| public.verify(MESSAGE, &parsed).is_ok());
        }
    }

    ok
}

/// Valid signatures for message-length boundaries, including the QHS-E
/// differential check.
#[must_use]
#[inline]
#[allow(
    clippy::large_stack_arrays,
    clippy::too_many_lines,
    reason = "the fixed QHS-4/4.2 signatures are 14-18 KB and each version has a fixed layout"
)]
pub fn attack_message_boundaries() -> bool {
    let lengths = [0_usize, 1, 31, 32, 33, 63, 64, 65, 255, 256, 1_024];
    let mut ok = true;

    let Ok((mut private1, public1)) = qhs_keygen(&SEED) else {
        return false;
    };
    let Ok((mut private2, public2)) = qhs2_keygen(&SEED) else {
        return false;
    };
    let Ok((mut private3, public3)) = qhs3_keygen(&SEED) else {
        return false;
    };
    for length in lengths {
        let message = vec![0x5a_u8; length];
        let Ok(signature1) = private1.sign(&message) else {
            return false;
        };
        let bytes1 = signature1.to_bytes();
        ok &= public1.verify(&message, &signature1).is_ok();
        ok &= verify_qhs1(&public1.to_bytes(), &message, &bytes1).is_ok();
        let Ok(signature2) = private2.sign(&message) else {
            return false;
        };
        let bytes2 = signature2.to_bytes();
        ok &= public2.verify(&message, &signature2).is_ok();
        ok &= verify_qhs2(&public2.to_bytes(), &message, &bytes2).is_ok();
        let Ok(signature3) = private3.sign(&message) else {
            return false;
        };
        let bytes3 = signature3.to_bytes();
        ok &= public3.verify(&message, &signature3).is_ok();
        ok &= verify_qhs3(&public3.to_bytes(), &message, &bytes3).is_ok();
        ok &= verify_qhs31(&public3.to_bytes(), &message, &bytes3).is_ok();
    }

    let Ok((mut private5, public5)) = qhs5_keygen(&SEED64) else {
        return false;
    };
    for length in lengths {
        let message = vec![0xa5_u8; length];
        let Ok(signature) = private5.sign(&message) else {
            return false;
        };
        ok &= public5.verify(&message, &signature).is_ok();
    }

    let Ok((mut private6, public6)) = qhs6_keygen(&SEED64, &SEED) else {
        return false;
    };
    for length in lengths {
        let message = vec![0x3c_u8; length];
        let Ok(signature) = private6.sign(&message) else {
            return false;
        };
        ok &= public6.verify(&message, &signature).is_ok();
    }

    let Ok((private4, public4)) = qhs4_keygen(&SEED) else {
        return false;
    };
    let Ok((private42, public42)) = qhs42_keygen(&SEED) else {
        return false;
    };
    for length in [0_usize, 1, 32, 64, 256] {
        let message = vec![0x11_u8; length];
        let Ok(signature4) = private4.sign(&message) else {
            return false;
        };
        ok &= public4.verify(&message, &signature4).is_ok();
        let Ok(signature42) = private42.sign(&message) else {
            return false;
        };
        ok &= public42.verify(&message, &signature42).is_ok();
    }

    ok
}

/// Flips every public-key byte and checks that parsing or verification rejects.
#[must_use]
#[inline]
#[allow(
    clippy::too_many_lines,
    reason = "one fixed public-key layout per signature version"
)]
pub fn attack_public_key_mutations() -> bool {
    let mut ok = true;

    let Ok((mut private1, public1)) = qhs_keygen(&SEED) else {
        return false;
    };
    let Ok(signature1) = private1.sign(MESSAGE) else {
        return false;
    };
    let key1 = public1.to_bytes();
    for offset in 0..key1.len() {
        let mut mutated = key1;
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 1;
        }
        if let Ok(parsed) = QhsPublicKey::from_bytes(&mutated) {
            ok &= parsed.verify(MESSAGE, &signature1).is_err();
        }
    }

    let Ok((mut private2, public2)) = qhs2_keygen(&SEED) else {
        return false;
    };
    let Ok(signature2) = private2.sign(MESSAGE) else {
        return false;
    };
    let key2 = public2.to_bytes();
    for offset in 0..key2.len() {
        let mut mutated = key2;
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 1;
        }
        if let Ok(parsed) = Qhs2PublicKey::from_bytes(&mutated) {
            ok &= parsed.verify(MESSAGE, &signature2).is_err();
        }
    }

    let Ok((mut private3, public3)) = qhs3_keygen(&SEED) else {
        return false;
    };
    let Ok(signature3) = private3.sign(MESSAGE) else {
        return false;
    };
    let key3 = public3.to_bytes();
    for offset in 0..key3.len() {
        let mut mutated = key3;
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 1;
        }
        if let Ok(parsed) = Qhs3PublicKey::from_bytes(&mutated) {
            ok &= parsed.verify(MESSAGE, &signature3).is_err();
        }
    }

    let Ok((private4, public4)) = qhs4_keygen(&SEED) else {
        return false;
    };
    let Ok(signature4) = private4.sign(MESSAGE) else {
        return false;
    };
    let key4 = public4.to_bytes();
    for offset in 0..key4.len() {
        let mut mutated = key4;
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 1;
        }
        if let Ok(parsed) = Qhs4PublicKey::from_bytes(&mutated) {
            ok &= parsed.verify(MESSAGE, &signature4).is_err();
        }
    }

    let Ok((private42, public42)) = qhs42_keygen(&SEED) else {
        return false;
    };
    let Ok(signature42) = private42.sign(MESSAGE) else {
        return false;
    };
    let key42 = public42.to_bytes();
    for offset in 0..key42.len() {
        let mut mutated = key42;
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 1;
        }
        if let Ok(parsed) = Qhs42PublicKey::from_bytes(&mutated) {
            ok &= parsed.verify(MESSAGE, &signature42).is_err();
        }
    }

    let Ok((mut private5, public5)) = qhs5_keygen(&SEED64) else {
        return false;
    };
    let Ok(signature5) = private5.sign(MESSAGE) else {
        return false;
    };
    let key5 = public5.to_bytes();
    for offset in 0..key5.len() {
        let mut mutated = key5;
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 1;
        }
        if let Ok(parsed) = Qhs5PublicKey::from_bytes(&mutated) {
            ok &= parsed.verify(MESSAGE, &signature5).is_err();
        }
    }

    let Ok((mut private6, public6)) = qhs6_keygen(&SEED64, &SEED) else {
        return false;
    };
    let Ok(signature6) = private6.sign(MESSAGE) else {
        return false;
    };
    let key6 = public6.to_bytes();
    for offset in 0..key6.len() {
        let mut mutated = key6;
        if let Some(byte) = mutated.get_mut(offset) {
            *byte ^= 1;
        }
        if let Ok(parsed) = Qhs6PublicKey::from_bytes(&mutated) {
            ok &= parsed.verify(MESSAGE, &signature6).is_err();
        }
    }

    ok
}

/// Cross-version key and signature confusion checks.
#[must_use]
#[inline]
pub fn attack_cross_version() -> bool {
    let Ok((mut private1, public1)) = qhs_keygen(&SEED) else {
        return false;
    };
    let Ok((mut private2, public2)) = qhs2_keygen(&SEED) else {
        return false;
    };
    let Ok((mut private3, public3)) = qhs3_keygen(&SEED) else {
        return false;
    };
    let Ok((private4, public4)) = qhs4_keygen(&SEED) else {
        return false;
    };
    let Ok((private42, public42)) = qhs42_keygen(&SEED) else {
        return false;
    };
    let Ok((mut private5, public5)) = qhs5_keygen(&SEED64) else {
        return false;
    };
    let Ok((mut private6, public6)) = qhs6_keygen(&SEED64, &SEED) else {
        return false;
    };
    let Ok(signature1) = private1.sign(MESSAGE) else {
        return false;
    };
    let Ok(signature2) = private2.sign(MESSAGE) else {
        return false;
    };
    let Ok(signature3) = private3.sign(MESSAGE) else {
        return false;
    };
    let Ok(signature4) = private4.sign(MESSAGE) else {
        return false;
    };
    let Ok(signature42) = private42.sign(MESSAGE) else {
        return false;
    };
    let Ok(signature5) = private5.sign(MESSAGE) else {
        return false;
    };
    let Ok(signature6) = private6.sign(MESSAGE) else {
        return false;
    };

    let key1 = public1.to_bytes();
    let key2 = public2.to_bytes();
    let key3 = public3.to_bytes();
    let key4 = public4.to_bytes();
    let key42 = public42.to_bytes();
    let key5 = public5.to_bytes();
    let key6 = public6.to_bytes();

    let mut ok = true;
    ok &= Qhs2PublicKey::from_bytes(&key1).is_err();
    ok &= Qhs3PublicKey::from_bytes(&key1).is_err();
    ok &= QhsPublicKey::from_bytes(&key2).is_err();
    ok &= Qhs3PublicKey::from_bytes(&key2).is_err();
    ok &= QhsPublicKey::from_bytes(&key3).is_err();
    ok &= Qhs2PublicKey::from_bytes(&key3).is_err();
    ok &= Qhs42PublicKey::from_bytes(&key4).is_err();
    ok &= Qhs4PublicKey::from_bytes(&key42).is_err();
    let mut padded6 = [0_u8; 108];
    padded6[..72].copy_from_slice(&key5);
    ok &= Qhs6PublicKey::from_bytes(&padded6).is_err();
    let mut short5 = [0_u8; 72];
    short5.copy_from_slice(&key6[..72]);
    ok &= Qhs5PublicKey::from_bytes(&short5).is_err();
    ok &= Qhs5Signature::from_slice(&signature6.to_bytes()).is_err();
    ok &= Qhs6Signature::from_slice(&signature5.to_bytes()).is_err();
    ok &= Qhs6Signature::from_slice(&signature1.to_bytes()).is_err();
    ok &= Qhs5Signature::from_slice(&signature1.to_bytes()).is_err();
    ok &= Qhs42Signature::from_slice(&signature4.to_bytes()).is_err();
    ok &= Qhs4Signature::from_slice(&signature42.to_bytes()).is_err();
    ok &= verify_qhs1(&key2, MESSAGE, &signature1.to_bytes()).is_err();
    ok &= verify_qhs2(&key1, MESSAGE, &signature2.to_bytes()).is_err();
    ok &= verify_qhs3(&key1, MESSAGE, &signature3.to_bytes()).is_err();

    ok
}

/// QHS-6 component-mixing attacks with matching leaf indices.
#[must_use]
#[inline]
pub fn attack_qhs6_component_binding() -> bool {
    let Ok((mut private, public)) = qhs6_keygen(&SEED64, &SEED) else {
        return false;
    };
    let first_message = b"qhs6-binding-first";
    let second_message = b"qhs6-binding-second";
    let Ok(first) = private.sign(first_message) else {
        return false;
    };
    let Ok(second) = private.sign(second_message) else {
        return false;
    };
    let (Ok(first_leaf), Ok(first_qhs5), Ok(first_ed)) = (
        first.leaf_index(),
        first.qhs5_signature(),
        first.ed25519_signature(),
    ) else {
        return false;
    };
    let (Ok(second_leaf), Ok(second_qhs5), Ok(second_ed)) = (
        second.leaf_index(),
        second.qhs5_signature(),
        second.ed25519_signature(),
    ) else {
        return false;
    };

    let mut ok = true;
    // Matching leaf index, but the Ed25519 component is from the other message.
    ok &= !Qhs6Signature::from_parts(second_leaf, second_qhs5, first_ed)
        .is_ok_and(|mixed| public.verify(second_message, &mixed).is_ok());
    ok &= !Qhs6Signature::from_parts(first_leaf, first_qhs5, second_ed)
        .is_ok_and(|mixed| public.verify(first_message, &mixed).is_ok());

    // Zero Ed25519 component.
    ok &= !Qhs6Signature::from_parts(
        first_leaf,
        first_qhs5,
        Ed25519Signature::from_bytes([0_u8; 64]),
    )
    .is_ok_and(|mixed| public.verify(first_message, &mixed).is_ok());

    // The embedded QHS-5 signature must not verify against the raw message.
    ok &= public
        .qhs5_public_key()
        .is_ok_and(|qhs5_public| qhs5_public.verify(first_message, &first_qhs5).is_err());

    // A QHS-5 component from a different key must not verify.
    let Ok((mut other_private, _)) = qhs6_keygen(&[11_u8; 64], &[12_u8; 32]) else {
        return false;
    };
    let Ok(other_signature) = other_private.sign(first_message) else {
        return false;
    };
    if let (Ok(other_leaf), Ok(other_qhs5)) = (
        other_signature.leaf_index(),
        other_signature.qhs5_signature(),
    ) {
        ok &= !Qhs6Signature::from_parts(other_leaf, other_qhs5, first_ed)
            .is_ok_and(|mixed| public.verify(first_message, &mixed).is_ok());
    } else {
        ok = false;
    }

    ok
}

/// Ed25519 small-order, non-canonical, and malleability edge cases.
#[must_use]
#[inline]
pub fn attack_ed25519_edge_cases() -> bool {
    let mut ok = true;

    let identity = {
        let mut bytes = [0_u8; 32];
        bytes[0] = 1;
        bytes
    };
    let negative_one = {
        let mut bytes = [0xff_u8; 32];
        bytes[0] = 0xec;
        bytes[31] = 0x7f;
        bytes
    };
    let order_four_zero = [0_u8; 32];
    let order_four_sign = {
        let mut bytes = [0_u8; 32];
        bytes[31] = 0x80;
        bytes
    };
    for key in [
        identity,
        negative_one,
        order_four_zero,
        order_four_sign,
        [0xff_u8; 32],
    ] {
        ok &= Ed25519PublicKey::from_bytes(&key).is_err();
    }

    let private = Ed25519PrivateKey::from_seed([7_u8; 32]);
    let public = private.public_key();
    let signature = private.sign(MESSAGE);
    let valid = signature.to_bytes();

    let mut identity_r = valid;
    identity_r[..32].copy_from_slice(&identity);
    ok &= public
        .verify(MESSAGE, &Ed25519Signature::from_bytes(identity_r))
        .is_err();

    let mut zero_s = valid;
    zero_s[32..].fill(0);
    ok &= public
        .verify(MESSAGE, &Ed25519Signature::from_bytes(zero_s))
        .is_err();

    // S = L is non-canonical.
    let order_l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut s_order = valid;
    s_order[32..].copy_from_slice(&order_l);
    ok &= public
        .verify(MESSAGE, &Ed25519Signature::from_bytes(s_order))
        .is_err();

    // S = valid S + L, if it fits in 256 bits.
    let mut s_plus_l = valid;
    let mut carry = 0_u16;
    for (slot, l_byte) in s_plus_l[32..].iter_mut().zip(order_l.iter()) {
        let sum = u16::from(*slot)
            .wrapping_add(u16::from(*l_byte))
            .wrapping_add(carry);
        *slot = u8::try_from(sum & 0xff).unwrap_or(0);
        carry = sum.wrapping_shr(8);
    }
    ok &= carry == 0;
    ok &= public
        .verify(MESSAGE, &Ed25519Signature::from_bytes(s_plus_l))
        .is_err();

    ok
}
