//! Small bounded-conversion and fixed-array helpers.

/// Returns the low 64 bits of a `u128` without an unchecked cast.
#[must_use]
#[inline]
pub(crate) fn low_u64(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).unwrap_or(0)
}

/// Reads a fixed-array limb without raw indexing.
#[must_use]
#[inline]
pub(crate) fn limb<const N: usize>(limbs: &[u64; N], index: usize) -> u64 {
    limbs.get(index).copied().unwrap_or(0)
}

/// Writes a fixed-array limb without raw indexing.
#[inline]
pub(crate) fn set_limb<const N: usize>(limbs: &mut [u64; N], index: usize, value: u64) {
    if let Some(slot) = limbs.get_mut(index) {
        *slot = value;
    }
}

/// Reads a byte from a fixed-size byte array without raw indexing.
#[must_use]
#[inline]
pub(crate) fn byte<const N: usize>(bytes: &[u8; N], index: usize) -> u8 {
    bytes.get(index).copied().unwrap_or(0)
}
