//! BLAKE-512 (the SHA-3 finalist, not BLAKE2), which circomlib's EdDSA uses.
//!
//! Written here because the `blake-hash` crate panics on aarch64: its 64-bit
//! rounds call `shuffle1230`, which ppv-lite86's generic backend leaves
//! `unimplemented!()`. Every Apple device is aarch64. Only the unsalted form is
//! needed, so the salt words are left out.

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

const U: [u64; 16] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
    0x4528_21e6_38d0_1377,
    0xbe54_66cf_34e9_0c6c,
    0xc0ac_29b7_c97c_50dd,
    0x3f84_d5b5_b547_0917,
    0x9216_d5d9_8979_fb1b,
    0xd131_0ba6_98df_b5ac,
    0x2ffd_72db_d01a_dfb7,
    0xb8e1_afed_6a26_7e96,
    0xba7c_9045_f12c_7f99,
    0x24a1_9947_b391_6cf7,
    0x0801_f2e2_858e_fc16,
    0x6369_20d8_7157_4e69,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const ROUNDS: usize = 16;

/// (a, b, c, d) word indices of the four column and four diagonal steps.
const STEPS: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

/// `t` is the count of message bits hashed through this block, or 0 for a
/// block that holds only padding.
fn compress(h: &mut [u64; 8], block: &[u8], t: u128) {
    let mut m = [0u64; 16];
    for (word, bytes) in m.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    let (t0, t1) = (t as u64, (t >> 64) as u64);

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&U[..8]);
    v[12] ^= t0;
    v[13] ^= t0;
    v[14] ^= t1;
    v[15] ^= t1;

    for round in 0..ROUNDS {
        let sigma = &SIGMA[round % SIGMA.len()];
        for (i, &[a, b, c, d]) in STEPS.iter().enumerate() {
            let (x, y) = (sigma[2 * i], sigma[2 * i + 1]);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[x] ^ U[y]);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(25);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[y] ^ U[x]);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(11);
        }
    }
    for (i, word) in h.iter_mut().enumerate() {
        *word ^= v[i] ^ v[i + 8];
    }
}

pub fn blake512(data: &[u8]) -> [u8; 64] {
    let mut h = IV;
    let bits = data.len() as u128 * 8;

    let (blocks, rest) = data.as_chunks::<128>();
    let mut hashed = 0u128;
    for block in blocks {
        hashed += 1024;
        compress(&mut h, block, hashed);
    }

    // Padding: 0x80, zeros, a final 1 bit, then the 128-bit big-endian length.
    let end = if rest.len() < 112 { 128 } else { 256 };
    let mut pad = [0u8; 256];
    pad[..rest.len()].copy_from_slice(rest);
    pad[rest.len()] = 0x80;
    pad[end - 17] |= 1;
    pad[end - 16..end].copy_from_slice(&bits.to_be_bytes());
    compress(&mut h, &pad[..128], if rest.is_empty() { 0 } else { bits });
    if end == 256 {
        compress(&mut h, &pad[128..], 0);
    }

    let mut out = [0u8; 64];
    for (bytes, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(h) {
        *bytes = word.to_be_bytes();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::blake512;

    // The two BLAKE-512 examples in the SHA-3 submission.
    #[test]
    fn specification_vectors() {
        assert_eq!(
            hex::encode(blake512(&[0])),
            "97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4\
             ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3"
        );
        assert_eq!(
            hex::encode(blake512(&[0; 144])),
            "313717d608e9cf758dcb1eb0f0c3cf9fc150b2d500fb33f51c52afc99d358a2f\
             1374b8a38bba7974e7f6ef79cab16f22ce1e649d6e01ad9589c213045d545dde"
        );
    }
}
