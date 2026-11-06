//! In-tree BLAKE3 implementation.
//!
//! This is a safe-Rust, allocation-free implementation of the BLAKE3 hash
//! function, keyed mode, derive-key mode, and 32-byte output.

#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    reason = "BLAKE3 compression follows the conventional v0..v15 / m0..m15 naming"
)]

use core::fmt;

use crate::Hash32;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const MAX_DEPTH: usize = 54;

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;
const DERIVE_KEY_CONTEXT: u32 = 32;
const DERIVE_KEY_MATERIAL: u32 = 64;

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

macro_rules! g {
    ($a:ident, $b:ident, $c:ident, $d:ident, $mx:expr, $my:expr) => {
        $a = $a.wrapping_add($b).wrapping_add($mx);
        $d = ($d ^ $a).rotate_right(16);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(12);
        $a = $a.wrapping_add($b).wrapping_add($my);
        $d = ($d ^ $a).rotate_right(8);
        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(7);
    };
}

#[allow(
    clippy::too_many_lines,
    reason = "the compression function is deliberately one flat, auditable block"
)]
fn compress(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut message = [0_u32; 16];
    for (slot, chunk) in message.iter_mut().zip(block.as_chunks::<4>().0) {
        *slot = u32::from_le_bytes(*chunk);
    }

    let [
        m0,
        m1,
        m2,
        m3,
        m4,
        m5,
        m6,
        m7,
        m8,
        m9,
        m10,
        m11,
        m12,
        m13,
        m14,
        m15,
    ] = message;
    let [c0, c1, c2, c3, c4, c5, c6, c7] = *cv;
    let [iv0, iv1, iv2, iv3, ..] = IV;
    let [b0, b1, b2, b3, b4, b5, b6, b7] = counter.to_le_bytes();
    let counter_low = u32::from_le_bytes([b0, b1, b2, b3]);
    let counter_high = u32::from_le_bytes([b4, b5, b6, b7]);

    let mut v0 = c0;
    let mut v1 = c1;
    let mut v2 = c2;
    let mut v3 = c3;
    let mut v4 = c4;
    let mut v5 = c5;
    let mut v6 = c6;
    let mut v7 = c7;
    let mut v8 = iv0;
    let mut v9 = iv1;
    let mut v10 = iv2;
    let mut v11 = iv3;
    let mut v12 = counter_low;
    let mut v13 = counter_high;
    let mut v14 = block_len;
    let mut v15 = flags;

    let mut m0 = m0;
    let mut m1 = m1;
    let mut m2 = m2;
    let mut m3 = m3;
    let mut m4 = m4;
    let mut m5 = m5;
    let mut m6 = m6;
    let mut m7 = m7;
    let mut m8 = m8;
    let mut m9 = m9;
    let mut m10 = m10;
    let mut m11 = m11;
    let mut m12 = m12;
    let mut m13 = m13;
    let mut m14 = m14;
    let mut m15 = m15;

    for _ in 0..7 {
        g!(v0, v4, v8, v12, m0, m1);
        g!(v1, v5, v9, v13, m2, m3);
        g!(v2, v6, v10, v14, m4, m5);
        g!(v3, v7, v11, v15, m6, m7);
        g!(v0, v5, v10, v15, m8, m9);
        g!(v1, v6, v11, v12, m10, m11);
        g!(v2, v7, v8, v13, m12, m13);
        g!(v3, v4, v9, v14, m14, m15);

        let (n0, n1, n2, n3, n4, n5, n6, n7) = (m2, m6, m3, m10, m7, m0, m4, m13);
        let (n8, n9, n10, n11, n12, n13, n14, n15) = (m1, m11, m12, m5, m9, m14, m15, m8);
        m0 = n0;
        m1 = n1;
        m2 = n2;
        m3 = n3;
        m4 = n4;
        m5 = n5;
        m6 = n6;
        m7 = n7;
        m8 = n8;
        m9 = n9;
        m10 = n10;
        m11 = n11;
        m12 = n12;
        m13 = n13;
        m14 = n14;
        m15 = n15;
    }

    [
        v0 ^ v8,
        v1 ^ v9,
        v2 ^ v10,
        v3 ^ v11,
        v4 ^ v12,
        v5 ^ v13,
        v6 ^ v14,
        v7 ^ v15,
        v8 ^ c0,
        v9 ^ c1,
        v10 ^ c2,
        v11 ^ c3,
        v12 ^ c4,
        v13 ^ c5,
        v14 ^ c6,
        v15 ^ c7,
    ]
}

const fn first8(output: [u32; 16]) -> [u32; 8] {
    let [a, b, c, d, e, f, g, h, ..] = output;
    [a, b, c, d, e, f, g, h]
}

fn hash_from_words(words: [u32; 8]) -> Hash32 {
    let mut bytes = [0_u8; 32];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Hash32::from_bytes(bytes)
}

fn hash_from_output(output: [u32; 16]) -> Hash32 {
    hash_from_words(first8(output))
}

fn words_from_hash(hash: Hash32) -> [u32; 8] {
    let mut words = [0_u32; 8];
    for (slot, chunk) in words.iter_mut().zip(hash.as_bytes().as_chunks::<4>().0) {
        *slot = u32::from_le_bytes(*chunk);
    }
    words
}

/// A streaming BLAKE3 hasher with 32-byte output.
#[must_use = "a hasher does nothing until update/finalize is called"]
pub struct Hasher {
    key: [u32; 8],
    chunk_cv: [u32; 8],
    chunk_buf: [u8; CHUNK_LEN],
    chunk_len: usize,
    chunk_counter: u64,
    stack: [[u32; 8]; MAX_DEPTH],
    stack_len: usize,
    flags: u32,
}

impl Hasher {
    /// Creates a new unkeyed BLAKE3 hasher.
    #[inline]
    pub const fn new() -> Self {
        Self::new_with_key(IV, 0)
    }

    /// Creates a new keyed BLAKE3 hasher.
    #[inline]
    pub fn new_keyed(key: [u8; 32]) -> Self {
        let hash = Hash32::from_bytes(key);
        Self::new_with_key(words_from_hash(hash), KEYED_HASH)
    }

    /// Creates a new derive-key hasher for `context`.
    #[inline]
    pub fn new_derive_key(context: &[u8]) -> Self {
        let context_hash = hash32_with_key(IV, DERIVE_KEY_CONTEXT, context);
        Self::new_with_key(words_from_hash(context_hash), DERIVE_KEY_MATERIAL)
    }

    const fn new_with_key(key: [u32; 8], flags: u32) -> Self {
        Self {
            key,
            chunk_cv: key,
            chunk_buf: [0; CHUNK_LEN],
            chunk_len: 0,
            chunk_counter: 0,
            stack: [[0; 8]; MAX_DEPTH],
            stack_len: 0,
            flags,
        }
    }

    /// Feeds input bytes into the hasher.
    #[inline]
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_len == CHUNK_LEN {
                let output = self.finalize_chunk(false);
                self.push_chunk_cv(first8(output), self.chunk_counter);
                self.chunk_counter = self.chunk_counter.wrapping_add(1);
                self.reset_chunk();
            }

            let want = CHUNK_LEN.saturating_sub(self.chunk_len);
            let take = want.min(input.len());
            let (head, tail) = input.split_at(take);
            let end = self.chunk_len.checked_add(take).unwrap_or(CHUNK_LEN);
            if let Some(destination) = self.chunk_buf.get_mut(self.chunk_len..end) {
                destination.copy_from_slice(head);
            }
            self.chunk_len = end;
            input = tail;
        }
    }

    /// Finishes the hash and returns 32 bytes.
    #[must_use]
    #[inline]
    pub fn finalize(mut self) -> Hash32 {
        if self.chunk_counter == 0 && self.stack_len == 0 {
            let output = self.finalize_chunk(true);
            return hash_from_output(output);
        }

        let output = self.finalize_chunk(false);
        self.push_raw(first8(output));
        self.chunk_counter = self.chunk_counter.wrapping_add(1);
        self.combine_root()
    }

    fn reset_chunk(&mut self) {
        self.chunk_cv = self.key;
        self.chunk_len = 0;
        self.chunk_buf.fill(0);
    }

    fn finalize_chunk(&mut self, is_root: bool) -> [u32; 16] {
        let block_count = self.chunk_len.div_ceil(BLOCK_LEN).max(1);
        let mut block = [0_u8; BLOCK_LEN];
        let mut output = [0_u32; 16];

        for block_index in 0..block_count {
            let start = block_index.checked_mul(BLOCK_LEN).unwrap_or(0);
            let end = start
                .checked_add(BLOCK_LEN)
                .unwrap_or(CHUNK_LEN)
                .min(self.chunk_len);
            let block_len = end.saturating_sub(start);

            block.fill(0);
            if let (Some(source), Some(destination)) =
                (self.chunk_buf.get(start..end), block.get_mut(..block_len))
            {
                destination.copy_from_slice(source);
            }

            let is_last = block_index.checked_add(1).unwrap_or(block_count) == block_count;
            let mut block_flags = self.flags;
            if block_index == 0 {
                block_flags |= CHUNK_START;
            }
            if is_last {
                block_flags |= CHUNK_END;
                if is_root {
                    block_flags |= ROOT;
                }
            }

            output = compress(
                &self.chunk_cv,
                &block,
                self.chunk_counter,
                u32::try_from(block_len).unwrap_or(0),
                block_flags,
            );
            self.chunk_cv = first8(output);

            if is_last {
                return output;
            }
        }

        output
    }

    fn parent_output(&self, left: &[u32; 8], right: &[u32; 8], is_root: bool) -> [u32; 16] {
        let mut block = [0_u8; BLOCK_LEN];
        for (chunk, word) in block
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(left.iter().chain(right.iter()))
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        let mut flags = PARENT | self.flags;
        if is_root {
            flags |= ROOT;
        }
        compress(&self.key, &block, 0, 64, flags)
    }

    fn push_raw(&mut self, cv: [u32; 8]) {
        if let Some(slot) = self.stack.get_mut(self.stack_len) {
            *slot = cv;
            self.stack_len = self.stack_len.saturating_add(1);
        }
    }

    fn pop_raw(&mut self) -> Option<[u32; 8]> {
        let index = self.stack_len.checked_sub(1)?;
        self.stack_len = index;
        self.stack.get(index).copied()
    }

    fn push_chunk_cv(&mut self, cv: [u32; 8], mut chunk_index: u64) {
        self.push_raw(cv);
        while chunk_index & 1 == 1 {
            let right = self.pop_raw().unwrap_or(self.key);
            let left = self.pop_raw().unwrap_or(self.key);
            let output = self.parent_output(&left, &right, false);
            self.push_raw(first8(output));
            chunk_index = chunk_index.checked_shr(1).unwrap_or(0);
        }
    }

    fn combine_root(&mut self) -> Hash32 {
        let mut right = self.pop_raw().unwrap_or(self.key);
        loop {
            if self.stack_len == 0 {
                return hash_from_words(right);
            }
            let left = self.pop_raw().unwrap_or(self.key);
            let is_root = self.stack_len == 0;
            let output = self.parent_output(&left, &right, is_root);
            if is_root {
                return hash_from_output(output);
            }
            self.push_raw(first8(output));
            right = self.pop_raw().unwrap_or(self.key);
        }
    }
}

impl Default for Hasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Hasher {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hasher")
            .field("chunk_len", &self.chunk_len)
            .field("chunk_counter", &self.chunk_counter)
            .field("stack_len", &self.stack_len)
            .finish_non_exhaustive()
    }
}

fn hash32_with_key(key: [u32; 8], flags: u32, input: &[u8]) -> Hash32 {
    let mut hasher = Hasher::new_with_key(key, flags);
    hasher.update(input);
    hasher.finalize()
}

/// Computes the 32-byte BLAKE3 hash of `input`.
#[must_use]
#[inline]
pub fn hash32(input: &[u8]) -> Hash32 {
    hash32_with_key(IV, 0, input)
}

/// Computes a 32-byte BLAKE3 derive-key output.
#[must_use]
#[inline]
pub fn derive_key32(context: &[u8], material: &[u8]) -> Hash32 {
    let context_hash = hash32_with_key(IV, DERIVE_KEY_CONTEXT, context);
    let key = words_from_hash(context_hash);
    hash32_with_key(key, DERIVE_KEY_MATERIAL, material)
}

#[cfg(test)]
mod tests {
    use super::{derive_key32, hash32};
    use crate::Hash32;

    fn hex(bytes: [u8; 32]) -> std::string::String {
        let mut output = std::string::String::new();
        for byte in bytes {
            output.push_str(&std::format!("{byte:02x}"));
        }
        output
    }

    #[test]
    fn empty_vector() {
        let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        assert_eq!(hex(hash32(b"").to_bytes()), expected);
    }

    #[test]
    fn abc_vector() {
        let expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
        assert_eq!(hex(hash32(b"abc").to_bytes()), expected);
    }

    #[test]
    fn derive_key_vector() {
        let context = b"qWp v1 message braid";
        let material = b"abc";
        assert_eq!(
            hex(derive_key32(context, material).to_bytes()),
            "32c0b618ef521ece7f0c8118f61e523e370a76b8b6e810a9efb1e6b6f9549941"
        );
        assert_eq!(
            hex(derive_key32(context, b"").to_bytes()),
            "391aca889ad402be0b8a4b52f7d3ee4b40e226882a905e8ef9fa7dbaab5b5e0a"
        );
    }

    #[test]
    fn keyed_vector() {
        let key = [7_u8; 32];
        let mut hasher = super::Hasher::new_keyed(key);
        hasher.update(b"message");
        assert_eq!(
            hex(hasher.finalize().to_bytes()),
            "1e9ebc6f3294d7315b443bdf6d9814ab1623206b854a20efbf4e3677dda920fd"
        );
    }

    #[test]
    fn hash32_is_deterministic() {
        let first = hash32(b"qWp");
        let second = hash32(b"qWp");
        assert_eq!(first, second);
        assert_ne!(first, hash32(b"qwp"));
    }

    #[test]
    fn keyed_hash_is_deterministic() {
        let key = [7_u8; 32];
        let mut first = super::Hasher::new_keyed(key);
        first.update(b"message");
        let mut second = super::Hasher::new_keyed(key);
        second.update(b"message");
        assert_eq!(first.finalize(), second.finalize());
    }

    #[test]
    fn empty_hash_is_not_zero() {
        assert_ne!(hash32(b""), Hash32::from_bytes([0; 32]));
    }

    fn pattern(len: usize) -> std::vec::Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect()
    }

    #[test]
    fn long_vectors() {
        let vectors = [
            (
                1024,
                "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            ),
            (
                1025,
                "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            ),
            (
                2048,
                "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            ),
            (
                4096,
                "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
            ),
            (
                10000,
                "5f81f9e4ab67627b6b036d5d4e3bc40d9d3daa6fcc2b6dd07ab2bbf0a877da54",
            ),
        ];
        for (length, expected) in vectors {
            assert_eq!(hex(hash32(&pattern(length)).to_bytes()), expected);
        }
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = pattern(3000);
        let mut hasher = super::Hasher::new();
        for chunk in data.chunks(37) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), hash32(&data));
    }
}
