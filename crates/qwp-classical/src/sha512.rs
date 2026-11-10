//! SHA-512 (FIPS 180-4).

use core::fmt;

const BLOCK_BYTES: usize = 128;
const DIGEST_BYTES: usize = 64;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// A streaming SHA-512 hasher.
#[must_use = "a hasher does nothing until update/finalize is called"]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    total_len: u128,
}

impl Sha512 {
    /// Creates a new SHA-512 hasher.
    #[inline]
    pub const fn new() -> Self {
        Self {
            state: IV,
            buffer: [0; BLOCK_BYTES],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feeds bytes into the hasher.
    #[inline]
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.buffer_len == BLOCK_BYTES {
                compress(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
            let want = BLOCK_BYTES.saturating_sub(self.buffer_len);
            let take = want.min(input.len());
            let end = self.buffer_len.saturating_add(take);
            if let (Some(destination), Some(source)) =
                (self.buffer.get_mut(self.buffer_len..end), input.get(..take))
            {
                destination.copy_from_slice(source);
            }
            self.buffer_len = end;
            self.total_len = self
                .total_len
                .saturating_add(u128::try_from(take).unwrap_or(u128::MAX));
            if let Some(tail) = input.get(take..) {
                input = tail;
            } else {
                input = &[];
            }
        }
    }

    /// Finishes the hash and returns 64 bytes.
    #[must_use]
    #[inline]
    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        let bit_len = self.total_len.saturating_mul(8);
        self.update(&[0x80]);
        while self.buffer_len != 112 {
            self.update(&[0]);
        }
        self.update(&bit_len.to_be_bytes());
        if self.buffer_len == BLOCK_BYTES {
            compress(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }
        let mut output = [0_u8; DIGEST_BYTES];
        for (slot, word) in output
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(self.state.iter())
        {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        output
    }
}

impl Default for Sha512 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sha512 {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Sha512").finish_non_exhaustive()
    }
}

/// Computes a one-shot SHA-512 hash.
#[must_use]
#[inline]
pub fn sha512(input: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    hasher.finalize()
}

fn compress(state: &mut [u64; 8], block: &[u8; BLOCK_BYTES]) {
    let mut w = [0_u64; 80];
    for (index, chunk) in block.as_chunks::<8>().0.iter().enumerate() {
        if let Some(slot) = w.get_mut(index) {
            *slot = u64::from_be_bytes(*chunk);
        }
    }
    for index in 16..80 {
        let word = crate::util::limb(&w, index - 15);
        let s0 = word.rotate_right(1) ^ word.rotate_right(8) ^ (word >> 7);
        let word = crate::util::limb(&w, index - 2);
        let s1 = word.rotate_right(19) ^ word.rotate_right(61) ^ (word >> 6);
        let value = crate::util::limb(&w, index - 16)
            .wrapping_add(s0)
            .wrapping_add(crate::util::limb(&w, index - 7))
            .wrapping_add(s1);
        crate::util::set_limb(&mut w, index, value);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for index in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K.get(index).copied().unwrap_or(0))
            .wrapping_add(crate::util::limb(&w, index));
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::{Sha512, sha512};

    fn hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write;
        let mut output = std::string::String::new();
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn empty_vector() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                .replace(' ', "")
        );
    }

    #[test]
    fn abc_vector() {
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(' ', "")
        );
    }

    #[test]
    fn default_debug_and_long_input() {
        let default = Sha512::default();
        let debug = std::format!("{default:?}");
        assert!(debug.starts_with("Sha512"));
        let input = [0x5a_u8; 300];
        let one_shot = sha512(&input);
        let mut hasher = Sha512::new();
        hasher.update(&input[..111]);
        hasher.update(&input[111..128]);
        hasher.update(&input[128..]);
        assert_eq!(hasher.finalize(), one_shot);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut hasher = Sha512::new();
        hasher.update(b"The quick brown ");
        hasher.update(b"fox jumps over the lazy dog");
        assert_eq!(
            hex(&hasher.finalize()),
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64\
             2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
                .replace(' ', "")
        );
    }
}
