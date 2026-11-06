//! qWp core error types.

use core::fmt;

/// Errors produced by qWp core types and parsers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A length is outside the fixed qWp layout.
    InvalidLength,
    /// A braid generator is zero or outside `-7..=7`.
    InvalidGenerator,
    /// A padding byte or padding generator is not zero.
    InvalidPadding,
    /// A polynomial degree is outside `-64..=64`.
    DegreeOutOfRange,
    /// A checked arithmetic operation overflowed.
    ArithmeticOverflow,
    /// An entropy source failed.
    EntropyFailure,
    /// The platform does not provide the requested capability.
    UnsupportedPlatform,
    /// The one-time signature key has no leaves left.
    KeyExhausted,
    /// Signature verification failed.
    VerificationFailed,
}

impl fmt::Display for CryptoError {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLength => "invalid length",
            Self::InvalidGenerator => "invalid braid generator",
            Self::InvalidPadding => "invalid padding",
            Self::DegreeOutOfRange => "degree out of range",
            Self::ArithmeticOverflow => "arithmetic overflow",
            Self::EntropyFailure => "entropy failure",
            Self::UnsupportedPlatform => "unsupported platform",
            Self::KeyExhausted => "key exhausted",
            Self::VerificationFailed => "verification failed",
        };
        formatter.write_str(message)
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoError;

    #[test]
    fn display_covers_every_variant() {
        let cases = [
            (CryptoError::InvalidLength, "invalid length"),
            (CryptoError::InvalidGenerator, "invalid braid generator"),
            (CryptoError::InvalidPadding, "invalid padding"),
            (CryptoError::DegreeOutOfRange, "degree out of range"),
            (CryptoError::ArithmeticOverflow, "arithmetic overflow"),
            (CryptoError::EntropyFailure, "entropy failure"),
            (CryptoError::UnsupportedPlatform, "unsupported platform"),
            (CryptoError::KeyExhausted, "key exhausted"),
            (CryptoError::VerificationFailed, "verification failed"),
        ];
        for (error, expected) in cases {
            assert_eq!(std::string::ToString::to_string(&error), expected);
        }
    }
}
