//! Extended-coordinate arithmetic on edwards25519.

use core::fmt;

use crate::field::Fe;

/// A point in extended coordinates `(X:Y:Z:T)` with `x = X/Z`, `y = Y/Z`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Point {
    pub(crate) x: Fe,
    pub(crate) y: Fe,
    pub(crate) z: Fe,
    pub(crate) t: Fe,
}

impl fmt::Debug for Point {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Point(")?;
        for byte in self.encode() {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

impl Point {
    pub(crate) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    pub(crate) const BASE: Self = Self {
        x: Fe::BASE_X,
        y: Fe::BASE_Y,
        z: Fe::ONE,
        t: Fe::BASE_T,
    };

    #[must_use]
    #[inline]
    pub(crate) fn add(self, other: Self) -> Self {
        let a = self.y.sub(self.x).mul(other.y.sub(other.x));
        let b = self.y.add(self.x).mul(other.y.add(other.x));
        let c = self.t.mul(Fe::D2).mul(other.t);
        let d = self.z.mul(Fe::from_u64(2)).mul(other.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn double(self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().mul(Fe::from_u64(2));
        let h = a.add(b);
        let e = h.sub(self.x.add(self.y).square());
        let g = a.sub(b);
        let f = c.add(g);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn scalar_mul(self, scalar: &[u8; 32]) -> Self {
        let mut result = Self::IDENTITY;
        for bit_index in (0..256).rev() {
            result = result.double();
            let sum = result.add(self);
            let bit = (scalar[bit_index / 8] >> (bit_index % 8)) & 1;
            result = Self::conditional_select(&result, &sum, u64::from(bit));
        }
        result
    }

    #[must_use]
    #[inline]
    pub(crate) fn conditional_select(first: &Self, second: &Self, choice: u64) -> Self {
        Self {
            x: Fe::conditional_select(&first.x, &second.x, choice),
            y: Fe::conditional_select(&first.y, &second.y, choice),
            z: Fe::conditional_select(&first.z, &second.z, choice),
            t: Fe::conditional_select(&first.t, &second.t, choice),
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn encode(self) -> [u8; 32] {
        let z_inverse = self.z.invert();
        let x = self.x.mul(z_inverse);
        let y = self.y.mul(z_inverse);
        let mut bytes = y.to_bytes();
        let sign = u8::from(x.is_negative()) << 7;
        bytes[31] |= sign;
        bytes
    }

    #[must_use]
    #[inline]
    pub(crate) fn decode(bytes: &[u8; 32]) -> Option<Self> {
        let sign = bytes[31] >> 7;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = Fe::from_bytes(&y_bytes);
        if y.to_bytes() != y_bytes {
            return None;
        }
        let y_squared = y.square();
        let u = y_squared.sub(Fe::ONE);
        let v = Fe::D.mul(y_squared).add(Fe::ONE);
        let (ok, mut x) = Fe::sqrt_ratio_i(u, v);
        if !ok {
            return None;
        }
        if x.is_zero() && sign == 1 {
            return None;
        }
        if x.is_negative() != (sign == 1) {
            x = x.neg();
        }
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    #[must_use]
    #[inline]
    pub(crate) fn equals(self, other: Self) -> bool {
        self.x.mul(other.z).equals(other.x.mul(self.z))
            && self.y.mul(other.z).equals(other.y.mul(self.z))
    }

    #[must_use]
    #[inline]
    pub(crate) fn is_identity(self) -> bool {
        self.x.is_zero() && self.y.equals(self.z)
    }

    #[must_use]
    #[inline]
    pub(crate) fn is_small_order(self) -> bool {
        self.double().double().double().is_identity()
    }
}

#[cfg(test)]
mod tests {
    use super::Point;
    use crate::field::Fe;

    #[test]
    fn basepoint_round_trip() {
        let encoded = Point::BASE.encode();
        let debug = std::format!("{:?}", Point::BASE);
        assert!(debug.starts_with("Point("));
        let decoded = Point::decode(&encoded).unwrap();
        assert!(decoded.equals(Point::BASE));
    }

    #[test]
    fn addition_matches_doubling() {
        assert!(Point::BASE.add(Point::BASE).equals(Point::BASE.double()));
    }

    #[test]
    fn identity_and_small_order() {
        assert!(Point::IDENTITY.is_identity());
        assert!(Point::IDENTITY.is_small_order());
        assert!(!Point::BASE.is_identity());
        assert!(!Point::BASE.is_small_order());
    }

    #[test]
    fn scalar_zero_and_order() {
        let zero = [0_u8; 32];
        assert!(Point::BASE.scalar_mul(&zero).is_identity());
        let order = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        assert!(Point::BASE.scalar_mul(&order).is_identity());
    }

    #[test]
    fn rejects_non_canonical_y() {
        let mut bytes = [0xff_u8; 32];
        bytes[0] = 0xed;
        bytes[31] = 0x7f;
        assert!(Point::decode(&bytes).is_none());
    }

    #[test]
    fn field_constants_are_on_curve() {
        let x2 = Point::BASE.x.square();
        let y2 = Point::BASE.y.square();
        assert_eq!(y2.sub(x2), Fe::ONE.add(Fe::D.mul(x2).mul(y2)));
    }
}
