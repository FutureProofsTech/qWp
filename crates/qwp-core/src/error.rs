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
        };
        formatter.write_str(message)
    }
}
