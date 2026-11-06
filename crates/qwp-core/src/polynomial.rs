//! Fixed-size Laurent polynomial representation.

use core::mem::size_of;

use crate::error::CryptoError;
use crate::{COEFF_COUNT, DEGREE_OFFSET_I32, PUBLIC_KEY_BYTES};

/// A 129-coefficient integer Laurent polynomial.
///
/// Degrees run from `-64` to `64`; coefficient index `64` is degree zero.
/// The exact size is 516 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: [i32; COEFF_COUNT],
}

impl Polynomial {
    /// Creates the zero polynomial.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            coefficients: [0; COEFF_COUNT],
        }
    }

    /// Parses a polynomial from its exact 516-byte little-endian representation.
    #[must_use]
    #[inline]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_BYTES]) -> Self {
        let mut polynomial = Self::new();
        for (slot, chunk) in polynomial
            .coefficients
            .iter_mut()
            .zip(bytes.as_chunks::<4>().0)
        {
            *slot = i32::from_le_bytes(*chunk);
        }
        polynomial
    }

    /// Serializes the polynomial into its exact 516-byte little-endian form.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let mut output = [0_u8; PUBLIC_KEY_BYTES];
        for (chunk, coefficient) in output
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.coefficients.iter())
        {
            chunk.copy_from_slice(&coefficient.to_le_bytes());
        }
        output
    }

    /// Returns the coefficient at `degree`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DegreeOutOfRange`] when `degree` is outside
    /// `-64..=64`.
    #[inline]
    pub fn coefficient(&self, degree: i32) -> Result<i32, CryptoError> {
        let index = degree
            .checked_add(DEGREE_OFFSET_I32)
            .ok_or(CryptoError::DegreeOutOfRange)?;
        let index = usize::try_from(index).map_err(|_| CryptoError::DegreeOutOfRange)?;
        self.coefficients
            .get(index)
            .copied()
            .ok_or(CryptoError::DegreeOutOfRange)
    }

    /// Sets the coefficient at `degree`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DegreeOutOfRange`] when `degree` is outside
    /// `-64..=64`.
    #[inline]
    pub fn set_coefficient(&mut self, degree: i32, value: i32) -> Result<(), CryptoError> {
        let index = degree
            .checked_add(DEGREE_OFFSET_I32)
            .ok_or(CryptoError::DegreeOutOfRange)?;
        let index = usize::try_from(index).map_err(|_| CryptoError::DegreeOutOfRange)?;
        let slot = self
            .coefficients
            .get_mut(index)
            .ok_or(CryptoError::DegreeOutOfRange)?;
        *slot = value;
        Ok(())
    }

    /// Returns `true` when every coefficient is zero.
    #[must_use]
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.coefficients
            .iter()
            .all(|coefficient| *coefficient == 0)
    }

    /// Returns the number of non-zero coefficients.
    #[must_use]
    #[inline]
    pub fn nonzero_count(&self) -> usize {
        self.coefficients
            .iter()
            .filter(|coefficient| **coefficient != 0)
            .count()
    }

    /// Returns the difference between the highest and lowest non-zero degrees.
    #[must_use]
    #[inline]
    pub fn degree_span(&self) -> Option<i32> {
        let mut minimum: Option<i32> = None;
        let mut maximum: Option<i32> = None;

        for (index, coefficient) in self.coefficients.iter().enumerate() {
            if *coefficient == 0 {
                continue;
            }
            let index = i32::try_from(index).ok()?;
            let degree = index.checked_sub(DEGREE_OFFSET_I32)?;
            minimum = Some(minimum.map_or(degree, |value| value.min(degree)));
            maximum = Some(maximum.map_or(degree, |value| value.max(degree)));
        }

        maximum?.checked_sub(minimum?)
    }

    /// Returns the exact size of the type in bytes.
    #[must_use]
    #[inline]
    pub const fn size() -> usize {
        size_of::<Self>()
    }
}

impl Default for Polynomial {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

const _: [(); PUBLIC_KEY_BYTES] = [(); size_of::<Polynomial>()];

#[cfg(test)]
mod tests {
    use super::Polynomial;
    use crate::error::CryptoError;
    use crate::{MAX_DEGREE, MIN_DEGREE, PUBLIC_KEY_BYTES};

    #[test]
    fn size_is_exact() {
        assert_eq!(Polynomial::size(), PUBLIC_KEY_BYTES);
    }

    #[test]
    fn zero_polynomial() {
        let polynomial = Polynomial::new();
        assert!(polynomial.is_zero());
        assert_eq!(polynomial.nonzero_count(), 0);
        assert_eq!(polynomial.degree_span(), None);
    }

    #[test]
    fn set_and_get() {
        let mut polynomial = Polynomial::new();
        polynomial.set_coefficient(0, 7).unwrap();
        polynomial.set_coefficient(MIN_DEGREE, -3).unwrap();
        polynomial.set_coefficient(MAX_DEGREE, 11).unwrap();
        assert_eq!(polynomial.coefficient(0), Ok(7));
        assert_eq!(polynomial.coefficient(MIN_DEGREE), Ok(-3));
        assert_eq!(polynomial.coefficient(MAX_DEGREE), Ok(11));
        assert_eq!(polynomial.nonzero_count(), 3);
        assert_eq!(polynomial.degree_span(), Some(128));
    }

    #[test]
    fn rejects_degree_out_of_range() {
        let polynomial = Polynomial::new();
        assert_eq!(
            polynomial.coefficient(MAX_DEGREE + 1),
            Err(CryptoError::DegreeOutOfRange)
        );
        assert_eq!(
            polynomial.coefficient(MIN_DEGREE - 1),
            Err(CryptoError::DegreeOutOfRange)
        );
    }

    #[test]
    fn round_trip() {
        let mut polynomial = Polynomial::new();
        polynomial.set_coefficient(-64, i32::MIN).unwrap();
        polynomial.set_coefficient(0, 1).unwrap();
        polynomial.set_coefficient(64, i32::MAX).unwrap();
        let bytes = polynomial.to_bytes();
        let parsed = Polynomial::from_bytes(&bytes);
        assert_eq!(parsed, polynomial);
    }
}
