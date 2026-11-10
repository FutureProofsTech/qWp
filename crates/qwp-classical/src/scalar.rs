//! Scalar arithmetic modulo the Ed25519 group order.

use core::fmt;

/// `L = 2^252 + 27742317777372353535851937790883648493`.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// A scalar modulo `L`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scalar(pub(crate) [u64; 4]);

impl fmt::Debug for Scalar {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Scalar(")?;
        for byte in self.to_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

impl Scalar {
    #[must_use]
    #[inline]
    pub(crate) fn from_hash64(hash: &[u8; 64]) -> Self {
        let mut words = [0_u64; 8];
        for (index, chunk) in hash.as_chunks::<8>().0.iter().enumerate() {
            if let Some(slot) = words.get_mut(index) {
                *slot = u64::from_le_bytes(*chunk);
            }
        }
        Self::reduce_512(words)
    }

    #[must_use]
    #[inline]
    pub(crate) fn from_bytes_reduce(bytes: &[u8; 32]) -> Self {
        let mut words = [0_u64; 8];
        for (index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            if let Some(slot) = words.get_mut(index) {
                *slot = u64::from_le_bytes(*chunk);
            }
        }
        Self::reduce_512(words)
    }

    #[must_use]
    #[inline]
    pub(crate) fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut words = [0_u64; 4];
        for (index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            if let Some(slot) = words.get_mut(index) {
                *slot = u64::from_le_bytes(*chunk);
            }
        }
        let (_, borrow) = sub_l(words, L);
        if borrow == 0 { None } else { Some(Self(words)) }
    }

    #[must_use]
    #[inline]
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for (chunk, word) in output.as_chunks_mut::<8>().0.iter_mut().zip(self.0.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        output
    }

    #[cfg(test)]
    #[must_use]
    #[inline]
    pub(crate) fn add(self, other: Self) -> Self {
        let mut sum = [0_u64; 4];
        let mut carry = 0_u128;
        for (slot, (left, right)) in sum.iter_mut().zip(self.0.iter().zip(other.0.iter())) {
            let value = u128::from(*left) + u128::from(*right) + carry;
            *slot = crate::util::low_u64(value);
            carry = value >> 64;
        }
        let (diff, borrow) = sub_l(sum, L);
        let mask = 0_u64.wrapping_sub(1_u64.wrapping_sub(borrow));
        let mut output = [0_u64; 4];
        for (slot, (value, replacement)) in output.iter_mut().zip(sum.iter().zip(diff.iter())) {
            *slot = (*value & !mask) | (*replacement & mask);
        }
        Self(output)
    }

    #[must_use]
    #[inline]
    pub(crate) fn mul_add(self, other: Self, addend: Self) -> Self {
        let mut product = [0_u64; 8];
        for (i, left) in self.0.iter().enumerate() {
            let mut carry = 0_u128;
            for (slot, right) in product.iter_mut().skip(i).take(4).zip(other.0.iter()) {
                let value = u128::from(*slot) + u128::from(*left) * u128::from(*right) + carry;
                *slot = crate::util::low_u64(value);
                carry = value >> 64;
            }
            crate::util::set_limb(
                &mut product,
                i.saturating_add(4),
                crate::util::low_u64(carry),
            );
        }
        let mut carry = 0_u128;
        for (slot, addend_limb) in product.iter_mut().take(4).zip(addend.0.iter()) {
            let value = u128::from(*slot) + u128::from(*addend_limb) + carry;
            *slot = crate::util::low_u64(value);
            carry = value >> 64;
        }
        for slot in product.iter_mut().skip(4) {
            let value = u128::from(*slot) + carry;
            *slot = crate::util::low_u64(value);
            carry = value >> 64;
        }
        Self::reduce_512(product)
    }

    #[cfg(test)]
    #[must_use]
    #[inline]
    pub(crate) fn is_zero(self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    #[must_use]
    #[inline]
    fn reduce_512(words: [u64; 8]) -> Self {
        let mut result = [0_u64; 4];
        for bit_index in (0..512).rev() {
            let bit = (crate::util::limb(&words, bit_index / 64) >> (bit_index % 64)) & 1;
            let mut carry = bit;
            for limb in &mut result {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            let (diff, borrow) = sub_l(result, L);
            let mask = 0_u64.wrapping_sub(1_u64.wrapping_sub(borrow));
            for (slot, replacement) in result.iter_mut().zip(diff.iter()) {
                *slot = (*slot & !mask) | (*replacement & mask);
            }
        }
        Self(result)
    }
}

fn sub_l(first: [u64; 4], second: [u64; 4]) -> ([u64; 4], u64) {
    let mut output = [0_u64; 4];
    let mut borrow = 0_u64;
    for ((slot, left), right) in output.iter_mut().zip(first.iter()).zip(second.iter()) {
        let (value, first_borrow) = left.overflowing_sub(*right);
        let (value, second_borrow) = value.overflowing_sub(borrow);
        *slot = value;
        borrow = u64::from(first_borrow || second_borrow);
    }
    (output, borrow)
}

#[cfg(test)]
mod tests {
    use super::{L, Scalar};

    #[test]
    fn reduce_known_hash() {
        let hash = crate::sha512::sha512(b"abc");
        let reduced = Scalar::from_hash64(&hash);
        assert_eq!(
            reduced.to_bytes(),
            [
                0xd1, 0x5d, 0xbe, 0xf2, 0x9a, 0xbf, 0x1f, 0xf2, 0x9f, 0x9c, 0xf9, 0x1c, 0x4b, 0x75,
                0xee, 0x0b, 0xb1, 0x01, 0x2c, 0xb0, 0x31, 0xd9, 0x60, 0x5d, 0x68, 0x4e, 0x84, 0x1d,
                0xf0, 0x34, 0xde, 0x0b
            ]
        );
    }

    #[test]
    fn mul_add_carry_vector() {
        let a = Scalar([
            0x7788_ea60_dc00_c35e,
            0x1978_29ef_e49e_55c7,
            0xce06_3f79_fe96_c6c3,
            0x0d1c_b1b3_095c_7fb7,
        ]);
        let b = Scalar([
            0x7e40_0777_c50e_1a49,
            0xe16b_8ebf_0d14_dc86,
            0xc60a_1f96_9e53_14e5,
            0x0ef7_b684_ebfd_e304,
        ]);
        let c = Scalar([
            0x5812_631a_5cf5_d3ec,
            0x14de_f9de_a2f7_9cd6,
            0x0000_0000_0000_0000,
            0x1000_0000_0000_0000,
        ]);
        let expected = Scalar([
            0xba0a_03f9_22b2_4584,
            0x591a_0b25_fa23_77d8,
            0x969b_0ffe_9b0f_a918,
            0x09dc_723a_a0a7_bdc1,
        ]);
        assert_eq!(a.mul_add(b, c).to_bytes(), expected.to_bytes());
    }

    #[test]
    fn debug_is_hex() {
        let debug = std::format!("{:?}", Scalar([1, 0, 0, 0]));
        assert!(debug.starts_with("Scalar("));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "generated fixed modular-arithmetic vectors"
    )]
    fn mul_add_vectors() {
        let vectors = [
            (
                [
                    0xee8971105e503a67,
                    0x452ec40a3193ca54,
                    0x6facaa5090e5e945,
                    0x0bf0239729645f8b,
                ],
                [
                    0xbc428d42fa882692,
                    0x95c5fb986980a81f,
                    0x2aa4857e8101e89a,
                    0x069535e825ece845,
                ],
                [
                    0x13ed748bb80e3b0d,
                    0xd64a3ce030a1f6d5,
                    0x527122dc57708107,
                    0x0eaece2906057c82,
                ],
                [
                    0x1b58afb855f70776,
                    0xfa7f70053e11c451,
                    0xddad11b8ce0fc8ec,
                    0x00084d53190babc0,
                ],
            ),
            (
                [
                    0x06e0f45856eaa301,
                    0x82bde024f7acee22,
                    0xb0d26ee6fa928906,
                    0x0d4b9985be99854a,
                ],
                [
                    0xe9c329a8b59a5969,
                    0x5473da68d3285151,
                    0x0a4de3e4ce9fb6a8,
                    0x03d56b9b3b788b66,
                ],
                [
                    0x41fad2962f927291,
                    0x6f05571896af0dea,
                    0xea80db0684ab5616,
                    0x0427e323f56ae7ea,
                ],
                [
                    0x445a272777c804db,
                    0x050307d983aa2ddc,
                    0x9b56d5d1938460c7,
                    0x02b48a9d1cb836a9,
                ],
            ),
            (
                [
                    0xfad2b6c50aa25068,
                    0x4d23bed52a04f77a,
                    0xdd533730fbb91133,
                    0x004ca619d50b612b,
                ],
                [
                    0xf70ae8c026784184,
                    0x5987baf13aa725cb,
                    0x578b24268a04f74f,
                    0x0c5a3809282fe557,
                ],
                [
                    0x03499f8452e1fbb0,
                    0x0f967bcc0ca02f4d,
                    0x71f2f9c4b6307bad,
                    0x0c6b519c141cb03e,
                ],
                [
                    0xee38c24051070ecd,
                    0x7adb497ad32be233,
                    0x3936b5edc16949b1,
                    0x0268b7c95993a408,
                ],
            ),
            (
                [
                    0x55e6fa5af79fcaa0,
                    0x340856933b0b6398,
                    0x29aa57a529ddf4c7,
                    0x04cdfbeb49cdbec7,
                ],
                [
                    0x75fb4415f46d4e1d,
                    0x2e93761b6aae0b74,
                    0xeb3f4d0a3e46cc1c,
                    0x05e5f556e0e3a17d,
                ],
                [
                    0x0b4634e66d47be83,
                    0xcc9a502c5d2c805c,
                    0x8930dd5b84459a03,
                    0x03712f1192f4b20d,
                ],
                [
                    0x3350ba053d3c875c,
                    0x585b3d4e282f0547,
                    0x9fcb6fa126f80330,
                    0x005078dfbf84a9a7,
                ],
            ),
            (
                [
                    0x4661d077090b3597,
                    0x71afc8adbf0976bd,
                    0x5e622929af973c3d,
                    0x09d5071e66dbcc44,
                ],
                [
                    0x9c4172e672fce34d,
                    0x4fd550c343abd549,
                    0x7e14fe2ebcba851b,
                    0x019c95a27afbd9be,
                ],
                [
                    0x72101a3f43df86ae,
                    0x383a03010783a82e,
                    0x22d57caa58569a9b,
                    0x0010abcdebc6222b,
                ],
                [
                    0x0d5b420adb4347bd,
                    0x246717a201eb6524,
                    0xe06f7440e5e1a9d4,
                    0x037062e1c9d64335,
                ],
            ),
            (
                [
                    0xf8373eebad17d536,
                    0xcdf91845a0277bbf,
                    0x1548e270ef12d18e,
                    0x038dcf7a07d5ba92,
                ],
                [
                    0xdf44c5b49a3a9565,
                    0xdcea2252301d8a84,
                    0x7d933dcd659e23c2,
                    0x08b954502e8cc39e,
                ],
                [
                    0x3563c1a6596091d6,
                    0x4cd68a77e6c0bc68,
                    0x50b7da40b9b34ee7,
                    0x0c6cc690d8a69224,
                ],
                [
                    0xea96d452c4b89c34,
                    0x8740cf8b871f3243,
                    0xbfbcff2a4f028f3f,
                    0x0e8e7bafdc51b319,
                ],
            ),
            (
                [
                    0x9de9feb51352e69d,
                    0x5e4fd35a4d04125f,
                    0xdd6f3010c8bec05c,
                    0x0d6a8f8e0a5b0380,
                ],
                [
                    0x29183eca3091a72b,
                    0x249176da14f4913e,
                    0x4e779665d14b5d87,
                    0x0aa690243b747bc0,
                ],
                [
                    0x336e875c6c9e62ea,
                    0x265ffc9c038c130b,
                    0xf3a30d701d1940b1,
                    0x0102432783954252,
                ],
                [
                    0xcfce86c0d8349dfc,
                    0xf7cfd5200bfa8c24,
                    0xcdee6e33d31fa97b,
                    0x0cbbbd938a2b3180,
                ],
            ),
            (
                [
                    0xff45ddffca9353f8,
                    0x64631da1574d8811,
                    0xddd1ddbf51c0d297,
                    0x07b9340e0a72aa2d,
                ],
                [
                    0x534aad5888183610,
                    0xc334629e968c80b9,
                    0xe6665e8ac81d4cd4,
                    0x0ea3a1b629e8fa09,
                ],
                [
                    0x708a8d146a2254b2,
                    0x5f2b18db064a2c49,
                    0x0700937ba99d4575,
                    0x0c6e0d1fde372e88,
                ],
                [
                    0x71e38dfd45ba1ac2,
                    0x4c3b87b72bd17ee6,
                    0xb18ac439e593528c,
                    0x0062f48413b34c05,
                ],
            ),
        ];
        for (a, b, c, expected) in vectors {
            let a = Scalar(a);
            let b = Scalar(b);
            let c = Scalar(c);
            assert_eq!(a.mul_add(b, c).to_bytes(), Scalar(expected).to_bytes());
        }
    }

    #[test]
    fn mul_add_small() {
        let two = Scalar([2, 0, 0, 0]);
        let three = Scalar([3, 0, 0, 0]);
        let four = Scalar([4, 0, 0, 0]);
        assert_eq!(two.mul_add(three, four).to_bytes()[0], 10);
    }

    #[test]
    fn mul_add_known() {
        let a = Scalar::from_canonical_bytes(&[
            0x7c, 0x2c, 0xac, 0x12, 0xe6, 0x9b, 0xe9, 0x6a, 0xe9, 0x06, 0x50, 0x65, 0x46, 0x23,
            0x85, 0xe8, 0xfc, 0xff, 0x27, 0x68, 0xd9, 0x80, 0xc0, 0xa3, 0xa5, 0x20, 0xf0, 0x06,
            0x90, 0x4d, 0xe9, 0x0f,
        ])
        .unwrap();
        let r = Scalar::from_canonical_bytes(&[
            0xf3, 0x89, 0x07, 0x30, 0x8c, 0x89, 0x3d, 0xea, 0xf2, 0x44, 0x78, 0x7d, 0xb4, 0xaf,
            0x53, 0x68, 0x22, 0x49, 0x10, 0x74, 0x18, 0xaf, 0xc2, 0xed, 0xc5, 0x8f, 0x75, 0xac,
            0x58, 0xa0, 0x74, 0x04,
        ])
        .unwrap();
        let k = Scalar::from_canonical_bytes(&[
            0x86, 0xea, 0xbc, 0x8e, 0x4c, 0x96, 0x19, 0x3d, 0x29, 0x05, 0x04, 0xe7, 0xc6, 0x00,
            0xdf, 0x6c, 0xf8, 0xd8, 0x25, 0x61, 0x31, 0xec, 0x2c, 0x13, 0x8a, 0x3e, 0x7e, 0x16,
            0x2e, 0x52, 0x54, 0x04,
        ])
        .unwrap();
        let zero = Scalar::from_canonical_bytes(&[0_u8; 32]).unwrap();
        assert_eq!(
            k.mul_add(a, zero).to_bytes(),
            [
                0x6c, 0x2e, 0x7b, 0xe5, 0x03, 0x1a, 0xfe, 0xc1, 0xd3, 0xd9, 0xc0, 0xf2, 0x67, 0x49,
                0x61, 0x03, 0xb0, 0x12, 0xe5, 0x7c, 0x41, 0xac, 0xfb, 0x36, 0x9f, 0xc1, 0xcb, 0x96,
                0x35, 0xda, 0x9b, 0x06
            ]
        );
        assert_eq!(
            k.mul_add(a, r).to_bytes(),
            [
                0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9,
                0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
                0x8e, 0x7a, 0x10, 0x0b
            ]
        );
    }

    #[test]
    fn canonical_check() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 1;
        assert!(Scalar::from_canonical_bytes(&bytes).is_some());
        let mut order = [0_u8; 32];
        for (chunk, word) in order.as_chunks_mut::<8>().0.iter_mut().zip(L.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        assert!(Scalar::from_canonical_bytes(&order).is_none());
    }

    #[test]
    fn add_wraps() {
        let mut one = [0_u8; 32];
        one[0] = 1;
        let one = Scalar::from_canonical_bytes(&one).unwrap();
        let minus_one = Scalar([L[0].wrapping_sub(1), L[1], L[2], L[3]]);
        assert!(minus_one.add(one).is_zero());
    }
}
