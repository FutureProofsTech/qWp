//! Field arithmetic modulo `2^255 - 19` using five 51-bit limbs.

use core::fmt;

pub(crate) const MASK51: u64 = (1_u64 << 51) - 1;
const P0: u64 = MASK51 - 18;
const P1: u64 = MASK51;
const P2: u64 = MASK51;
const P3: u64 = MASK51;
const P4: u64 = MASK51;

const P_MINUS_2: [u8; 32] = [
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

const P58: [u8; 32] = [
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];

/// An element of GF(2^255 - 19).
#[derive(Clone, Copy)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

impl PartialEq for Fe {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for Fe {}

impl fmt::Debug for Fe {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Fe(")?;
        for byte in self.to_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

impl Fe {
    pub(crate) const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);

    pub(crate) const D: Self = Self([
        0x34dca135978a3,
        0x1a8283b156ebd,
        0x5e7a26001c029,
        0x739c663a03cbb,
        0x52036cee2b6ff,
    ]);
    pub(crate) const D2: Self = Self([
        0x69b9426b2f159,
        0x35050762add7a,
        0x3cf44c0038052,
        0x6738cc7407977,
        0x2406d9dc56dff,
    ]);
    pub(crate) const SQRT_M1: Self = Self([
        0x61b274a0ea0b0,
        0xd5a5fc8f189d,
        0x7ef5e9cbd0c60,
        0x78595a6804c9e,
        0x2b8324804fc1d,
    ]);
    pub(crate) const BASE_X: Self = Self([
        0x62d608f25d51a,
        0x412a4b4f6592a,
        0x75b7171a4b31d,
        0x1ff60527118fe,
        0x216936d3cd6e5,
    ]);
    pub(crate) const BASE_Y: Self = Self([
        0x6666666666658,
        0x4cccccccccccc,
        0x1999999999999,
        0x3333333333333,
        0x6666666666666,
    ]);
    pub(crate) const BASE_T: Self = Self([
        0x68ab3a5b7dda3,
        0xeea2a5eadbb,
        0x2af8df483c27e,
        0x332b375274732,
        0x67875f0fd78b7,
    ]);

    #[must_use]
    #[inline]
    pub(crate) const fn from_u64(value: u64) -> Self {
        Self([value & MASK51, 0, 0, 0, 0])
    }

    #[must_use]
    #[inline]
    pub(crate) const fn from_bytes(bytes: &[u8; 32]) -> Self {
        let x0 = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let x1 = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let x2 = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let x3 = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        Self([
            x0 & MASK51,
            ((x0 >> 51) | (x1 << 13)) & MASK51,
            ((x1 >> 38) | (x2 << 26)) & MASK51,
            ((x2 >> 25) | (x3 << 39)) & MASK51,
            (x3 >> 12) & MASK51,
        ])
    }

    #[must_use]
    #[inline]
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut h = self.0;
        let mut carry = 0_u64;
        for limb in h.iter_mut().take(4) {
            let value = limb.wrapping_add(carry);
            *limb = value & MASK51;
            carry = value >> 51;
        }
        let carry_value = crate::util::limb(&h, 4).wrapping_add(carry);
        crate::util::set_limb(&mut h, 4, carry_value);
        carry = carry_value >> 51;
        crate::util::set_limb(&mut h, 4, carry_value & MASK51);
        let first = crate::util::limb(&h, 0).wrapping_add(carry.wrapping_mul(19));
        crate::util::set_limb(&mut h, 0, first);
        carry = first >> 51;
        crate::util::set_limb(&mut h, 0, first & MASK51);
        let second = crate::util::limb(&h, 1).wrapping_add(carry);
        crate::util::set_limb(&mut h, 1, second);

        let p = [P0, P1, P2, P3, P4];
        let mut diff = [0_u64; 5];
        let mut borrow = 0_u64;
        for ((slot, value), prime) in diff.iter_mut().zip(h.iter()).zip(p.iter()) {
            let sub = prime.wrapping_add(borrow);
            let (value, next) = value.overflowing_sub(sub);
            *slot = value;
            borrow = u64::from(next);
        }
        let mask = 0_u64.wrapping_sub(1_u64.wrapping_sub(borrow));
        for (slot, replacement) in h.iter_mut().zip(diff.iter()) {
            *slot = (*slot & !mask) | (*replacement & mask);
        }

        let w0 = crate::util::limb(&h, 0) | (crate::util::limb(&h, 1) << 51);
        let w1 = (crate::util::limb(&h, 1) >> 13) | (crate::util::limb(&h, 2) << 38);
        let w2 = (crate::util::limb(&h, 2) >> 26) | (crate::util::limb(&h, 3) << 25);
        let w3 = (crate::util::limb(&h, 3) >> 39) | (crate::util::limb(&h, 4) << 12);
        let mut output = [0_u8; 32];
        for (chunk, word) in output
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip([w0, w1, w2, w3])
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        output
    }

    #[must_use]
    #[inline]
    pub(crate) fn add(self, other: Self) -> Self {
        let mut limbs = [0_u128; 5];
        for (slot, (left, right)) in limbs.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            *slot = u128::from(*left) + u128::from(*right);
        }
        Self::carry_u128(limbs)
    }

    #[must_use]
    #[inline]
    pub(crate) fn sub(self, other: Self) -> Self {
        let mut limbs = [0_u128; 5];
        for (((slot, left), right), prime) in limbs
            .iter_mut()
            .zip(self.0.iter())
            .zip(other.0.iter())
            .zip([P0, P1, P2, P3, P4].iter())
        {
            *slot = u128::from(*left) + u128::from(*prime).wrapping_mul(2) - u128::from(*right);
        }
        Self::carry_u128(limbs)
    }

    #[must_use]
    #[inline]
    fn carry_u128(mut limbs: [u128; 5]) -> Self {
        for _ in 0..3 {
            let mut carry = 0_u128;
            for limb in &mut limbs {
                let value = limb.wrapping_add(carry);
                *limb = value & u128::from(MASK51);
                carry = value >> 51;
            }
            if let Some(first) = limbs.first_mut() {
                *first = first.wrapping_add(carry.wrapping_mul(19));
            }
        }
        let mut output = [0_u64; 5];
        for (slot, value) in output.iter_mut().zip(limbs.iter()) {
            *slot = crate::util::low_u64(*value);
        }
        let mut carry = 0_u64;
        for limb in &mut output {
            let value = limb.wrapping_add(carry);
            *limb = value & MASK51;
            carry = value >> 51;
        }
        let first = crate::util::limb(&output, 0).wrapping_add(carry.wrapping_mul(19));
        crate::util::set_limb(&mut output, 0, first);
        let mut carry = first >> 51;
        crate::util::set_limb(&mut output, 0, first & MASK51);
        let second = crate::util::limb(&output, 1).wrapping_add(carry);
        crate::util::set_limb(&mut output, 1, second);
        carry = second >> 51;
        crate::util::set_limb(&mut output, 1, second & MASK51);
        let third = crate::util::limb(&output, 2).wrapping_add(carry);
        crate::util::set_limb(&mut output, 2, third);
        Self(output)
    }

    #[must_use]
    #[inline]
    pub(crate) fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    #[must_use]
    #[inline]
    pub(crate) fn mul(self, other: Self) -> Self {
        let a = self.0;
        let b = other.0;
        let a0 = u128::from(a[0]);
        let a1 = u128::from(a[1]);
        let a2 = u128::from(a[2]);
        let a3 = u128::from(a[3]);
        let a4 = u128::from(a[4]);
        let b0 = u128::from(b[0]);
        let b1 = u128::from(b[1]);
        let b2 = u128::from(b[2]);
        let b3 = u128::from(b[3]);
        let b4 = u128::from(b[4]);

        let c0 = a0 * b0 + 19 * (a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1);
        let c1 = a0 * b1 + a1 * b0 + 19 * (a2 * b4 + a3 * b3 + a4 * b2);
        let c2 = a0 * b2 + a1 * b1 + a2 * b0 + 19 * (a3 * b4 + a4 * b3);
        let c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + 19 * (a4 * b4);
        let c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let mut h = [0_u64; 5];
        let mut carry = 0_u128;
        for (slot, value) in h.iter_mut().zip([c0, c1, c2, c3]) {
            let value = value + carry;
            *slot = crate::util::low_u64(value & u128::from(MASK51));
            carry = value >> 51;
        }
        let value = c4 + carry;
        crate::util::set_limb(&mut h, 4, crate::util::low_u64(value & u128::from(MASK51)));
        carry = value >> 51;
        let first =
            crate::util::limb(&h, 0).wrapping_add(crate::util::low_u64(carry).wrapping_mul(19));
        crate::util::set_limb(&mut h, 0, first);
        let mut carry = first >> 51;
        crate::util::set_limb(&mut h, 0, first & MASK51);
        let second = crate::util::limb(&h, 1).wrapping_add(carry);
        crate::util::set_limb(&mut h, 1, second);
        carry = second >> 51;
        crate::util::set_limb(&mut h, 1, second & MASK51);
        let third = crate::util::limb(&h, 2).wrapping_add(carry);
        crate::util::set_limb(&mut h, 2, third);
        carry = third >> 51;
        crate::util::set_limb(&mut h, 2, third & MASK51);
        let fourth = crate::util::limb(&h, 3).wrapping_add(carry);
        crate::util::set_limb(&mut h, 3, fourth);
        carry = fourth >> 51;
        crate::util::set_limb(&mut h, 3, fourth & MASK51);
        let fifth = crate::util::limb(&h, 4).wrapping_add(carry);
        crate::util::set_limb(&mut h, 4, fifth);
        carry = fifth >> 51;
        crate::util::set_limb(&mut h, 4, fifth & MASK51);
        let wrap = crate::util::limb(&h, 0).wrapping_add(carry.wrapping_mul(19));
        crate::util::set_limb(&mut h, 0, wrap);
        carry = wrap >> 51;
        crate::util::set_limb(&mut h, 0, wrap & MASK51);
        let last = crate::util::limb(&h, 1).wrapping_add(carry);
        crate::util::set_limb(&mut h, 1, last);
        Self(h)
    }

    #[must_use]
    #[inline]
    pub(crate) fn square(self) -> Self {
        self.mul(self)
    }

    #[must_use]
    #[inline]
    pub(crate) fn pow_bytes(self, exponent: &[u8; 32]) -> Self {
        let mut result = Self::ONE;
        for bit_index in (0..256).rev() {
            result = result.square();
            let bit = (crate::util::byte(exponent, bit_index / 8) >> (bit_index % 8)) & 1;
            let product = result.mul(self);
            result = Self::conditional_select(&result, &product, u64::from(bit));
        }
        result
    }

    #[must_use]
    #[inline]
    pub(crate) fn invert(self) -> Self {
        self.pow_bytes(&P_MINUS_2)
    }

    #[must_use]
    #[inline]
    pub(crate) fn pow_p58(self) -> Self {
        self.pow_bytes(&P58)
    }

    #[must_use]
    #[inline]
    pub(crate) fn conditional_select(first: &Self, second: &Self, choice: u64) -> Self {
        let mask = 0_u64.wrapping_sub(choice & 1);
        let mut output = [0_u64; 5];
        for (slot, (left, right)) in output.iter_mut().zip(first.0.iter().zip(second.0.iter())) {
            *slot = (*left & !mask) | (*right & mask);
        }
        Self(output)
    }

    #[must_use]
    #[inline]
    pub(crate) fn equals(self, other: Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    #[must_use]
    #[inline]
    pub(crate) fn is_zero(self) -> bool {
        self.to_bytes().iter().all(|byte| *byte == 0)
    }

    #[must_use]
    #[inline]
    pub(crate) fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Returns `(true, sqrt(u/v))` when the ratio is square.
    #[must_use]
    #[inline]
    pub(crate) fn sqrt_ratio_i(u: Self, v: Self) -> (bool, Self) {
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let r = u.mul(v3).mul(u.mul(v7).pow_p58());
        let check = v.mul(r.square());
        let correct = check.equals(u);
        let flipped = check.equals(u.neg());
        let r = Self::conditional_select(&r, &r.mul(Self::SQRT_M1), u64::from(flipped));
        (correct || flipped, r)
    }
}

#[cfg(test)]
mod tests {
    use super::Fe;

    #[test]
    fn constants_are_consistent() {
        assert_eq!(
            Fe::from_u64(121665)
                .neg()
                .mul(Fe::from_u64(121666).invert()),
            Fe::D
        );
        assert_eq!(Fe::D.add(Fe::D), Fe::D2);
        assert_eq!(Fe::SQRT_M1.square(), Fe::from_u64(1).neg());
    }

    #[test]
    fn basepoint_is_on_curve() {
        let x2 = Fe::BASE_X.square();
        let y2 = Fe::BASE_Y.square();
        let left = y2.sub(x2);
        let right = Fe::ONE.add(Fe::D.mul(x2).mul(y2));
        assert_eq!(left, right);
        assert_eq!(Fe::BASE_X.mul(Fe::BASE_Y), Fe::BASE_T);
    }

    #[test]
    fn equality_and_debug() {
        let one = Fe::from_u64(1);
        let two = Fe::from_u64(2);
        assert_ne!(one, two);
        assert_eq!(one, Fe::from_u64(1));
        let debug = std::format!("{one:?}");
        assert!(debug.starts_with("Fe("));
    }

    #[test]
    fn inversion_and_encoding() {
        let value = Fe::from_u64(1234567);
        assert_eq!(value.mul(value.invert()), Fe::ONE);
        let bytes = value.to_bytes();
        assert_eq!(Fe::from_bytes(&bytes), value);
        let mut p = [0xff_u8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(Fe::from_bytes(&p).is_zero());
    }

    #[test]
    fn sqrt_ratio_finds_one() {
        let (ok, root) = Fe::sqrt_ratio_i(Fe::ONE, Fe::ONE);
        assert!(ok);
        assert!(root.equals(Fe::ONE) || root.equals(Fe::ONE.neg()));
    }
}
