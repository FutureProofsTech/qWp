//! Fixed-size braid words.

use core::fmt;
use core::mem::size_of;

use crate::error::CryptoError;
use crate::{BRAID_BYTES, MAX_CROSSINGS, MAX_GENERATOR, MIN_GENERATOR};

/// A braid word on eight strands with up to 32 crossings.
///
/// Layout: 32 signed crossing bytes followed by an eight-byte length.
/// The total size is exactly 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Braid {
    crossings: [i8; MAX_CROSSINGS],
    len: u64,
}

impl Braid {
    /// Creates an empty braid.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            crossings: [0; MAX_CROSSINGS],
            len: 0,
        }
    }

    /// Creates a braid from a slice of Artin generators.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] when the slice is longer than
    /// [`MAX_CROSSINGS`], and [`CryptoError::InvalidGenerator`] when a
    /// generator is zero or outside `-7..=7`.
    #[inline]
    pub fn from_generators(generators: &[i8]) -> Result<Self, CryptoError> {
        if generators.len() > MAX_CROSSINGS {
            return Err(CryptoError::InvalidLength);
        }

        let mut braid = Self::new();
        for (index, generator) in generators.iter().enumerate() {
            let slot = braid
                .crossings
                .get_mut(index)
                .ok_or(CryptoError::InvalidLength)?;
            *slot = *generator;
        }
        braid.len = u64::try_from(generators.len()).map_err(|_| CryptoError::InvalidLength)?;
        braid.validate()?;
        Ok(braid)
    }

    /// Parses a braid from its exact 40-byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error when the length is invalid, a generator is out of
    /// range, or padding bytes are non-zero.
    #[inline]
    pub fn from_bytes(bytes: &[u8; BRAID_BYTES]) -> Result<Self, CryptoError> {
        let mut braid = Self::new();

        for (slot, byte) in braid.crossings.iter_mut().zip(bytes.iter()) {
            *slot = i8::from_le_bytes([*byte]);
        }

        let length_start = BRAID_BYTES.saturating_sub(8);
        let length_bytes = bytes
            .get(length_start..BRAID_BYTES)
            .ok_or(CryptoError::InvalidLength)?;
        let mut length_word = [0_u8; 8];
        length_word.copy_from_slice(length_bytes);
        braid.len = u64::from_le_bytes(length_word);

        braid.validate()?;
        Ok(braid)
    }

    /// Serializes the braid into its exact 40-byte representation.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; BRAID_BYTES] {
        let mut output = [0_u8; BRAID_BYTES];

        for (index, crossing) in self.crossings.iter().enumerate() {
            if let Some(slot) = output.get_mut(index) {
                let [byte] = crossing.to_le_bytes();
                *slot = byte;
            }
        }

        let length_start = BRAID_BYTES.saturating_sub(8);
        if let Some(slot) = output.get_mut(length_start..BRAID_BYTES) {
            slot.copy_from_slice(&self.len.to_le_bytes());
        }

        output
    }

    /// Returns the active word length.
    #[must_use]
    #[inline]
    pub fn len(&self) -> u8 {
        u8::try_from(self.len).unwrap_or(0)
    }

    /// Returns `true` when the braid has no crossings.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the crossing at `index`, if it is active.
    #[must_use]
    #[inline]
    pub fn get(&self, index: usize) -> Option<i8> {
        if index < usize::try_from(self.len).unwrap_or(0) {
            self.crossings.get(index).copied()
        } else {
            None
        }
    }

    /// Iterates over the active crossings.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = i8> + '_ {
        let len = usize::try_from(self.len).unwrap_or(0);
        self.crossings.iter().take(len).copied()
    }

    /// Returns the active crossings as a slice.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[i8] {
        let len = usize::try_from(self.len).unwrap_or(0);
        self.crossings.get(..len).unwrap_or(&[])
    }

    /// Clears the braid in place.
    ///
    /// This is a best-effort wipe. Safe Rust cannot guarantee that the
    /// compiler keeps the writes.
    #[inline]
    pub fn clear(&mut self) {
        self.crossings.fill(0);
        self.len = 0;
    }

    /// Validates the internal invariants.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is too large, an active generator is
    /// invalid, or an inactive slot is non-zero.
    #[inline]
    pub fn validate(&self) -> Result<(), CryptoError> {
        let len = usize::try_from(self.len).map_err(|_| CryptoError::InvalidLength)?;
        if len > MAX_CROSSINGS {
            return Err(CryptoError::InvalidLength);
        }

        for (index, crossing) in self.crossings.iter().enumerate() {
            if index < len {
                if *crossing == 0 || !(MIN_GENERATOR..=MAX_GENERATOR).contains(crossing) {
                    return Err(CryptoError::InvalidGenerator);
                }
            } else if *crossing != 0 {
                return Err(CryptoError::InvalidPadding);
            }
        }

        Ok(())
    }

    /// Returns the exact size of the type in bytes.
    #[must_use]
    #[inline]
    pub const fn size() -> usize {
        size_of::<Self>()
    }
}

impl Default for Braid {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Braid {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Braid")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

const _: [(); BRAID_BYTES] = [(); size_of::<Braid>()];

#[cfg(test)]
mod tests {
    use super::Braid;
    use crate::error::CryptoError;
    use crate::{BRAID_BYTES, MAX_CROSSINGS};

    #[test]
    fn size_is_exact() {
        assert_eq!(Braid::size(), BRAID_BYTES);
    }

    #[test]
    fn empty_braid_is_valid() {
        let braid = Braid::new();
        assert!(braid.is_empty());
        assert_eq!(braid.len(), 0);
        assert_eq!(braid.validate(), Ok(()));
    }

    #[test]
    fn round_trip() {
        let braid = Braid::from_generators(&[1, -2, 7, -7]).unwrap();
        let bytes = braid.to_bytes();
        let parsed = Braid::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, braid);
        assert_eq!(parsed.as_slice(), &[1, -2, 7, -7]);
    }

    #[test]
    fn rejects_zero_generator() {
        assert_eq!(
            Braid::from_generators(&[0]),
            Err(CryptoError::InvalidGenerator)
        );
    }

    #[test]
    fn rejects_out_of_range_generator() {
        assert_eq!(
            Braid::from_generators(&[8]),
            Err(CryptoError::InvalidGenerator)
        );
        assert_eq!(
            Braid::from_generators(&[-8]),
            Err(CryptoError::InvalidGenerator)
        );
    }

    #[test]
    fn rejects_too_long() {
        let generators = [1_i8; MAX_CROSSINGS + 1];
        assert_eq!(
            Braid::from_generators(&generators),
            Err(CryptoError::InvalidLength)
        );
    }

    #[test]
    fn rejects_bad_padding() {
        let braid = Braid::from_generators(&[1, 2]).unwrap();
        let mut bytes = braid.to_bytes();
        bytes[3] = 1;
        assert_eq!(Braid::from_bytes(&bytes), Err(CryptoError::InvalidPadding));
    }

    #[test]
    fn rejects_bad_length() {
        let braid = Braid::new();
        let mut bytes = braid.to_bytes();
        let bad_length = (MAX_CROSSINGS as u64) + 1;
        bytes[32..40].copy_from_slice(&bad_length.to_le_bytes());
        assert_eq!(Braid::from_bytes(&bytes), Err(CryptoError::InvalidLength));
    }

    #[test]
    fn get_and_iterate() {
        let braid = Braid::from_generators(&[1, -2, 7]).unwrap();
        assert_eq!(braid.get(0), Some(1));
        assert_eq!(braid.get(1), Some(-2));
        assert_eq!(braid.get(2), Some(7));
        assert_eq!(braid.get(3), None);
        assert_eq!(
            braid.iter().collect::<std::vec::Vec<_>>(),
            std::vec![1, -2, 7]
        );
        assert_eq!(braid.as_slice(), &[1, -2, 7]);
    }

    #[test]
    fn empty_and_default_and_clear() {
        let mut braid = Braid::default();
        assert!(braid.is_empty());
        assert_eq!(braid.as_slice(), &[]);
        braid = Braid::from_generators(&[1, 2]).unwrap();
        braid.clear();
        assert!(braid.is_empty());
        assert_eq!(braid.get(0), None);
    }

    #[test]
    fn debug_is_redacted() {
        let braid = Braid::from_generators(&[1, 2, 3]).unwrap();
        let debug = std::format!("{braid:?}");
        assert!(debug.contains("Braid"));
        assert!(!debug.contains("crossings"));
    }

    #[test]
    fn empty_generator_slice_is_valid() {
        assert_eq!(Braid::from_generators(&[]), Ok(Braid::new()));
    }

    #[test]
    fn max_length_is_valid_and_len_is_reported() {
        let generators = [1_i8; MAX_CROSSINGS];
        let braid = Braid::from_generators(&generators).unwrap();
        assert_eq!(braid.len(), u8::try_from(MAX_CROSSINGS).unwrap());
        assert!(!braid.is_empty());
    }
}
