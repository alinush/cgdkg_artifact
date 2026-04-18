//! Hash-to-curve for BLS12-381 G1/G2 using blstrs.
//!
//! Uses blstrs's `hash_to_curve` inherent method on `G1Projective` /
//! `G2Projective`, which wraps blst's RFC 9380 SSWU implementation.

use blstrs::{G1Projective, G2Projective};

pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub fn hash_to_ecp(msg: &[u8], dst: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(msg, dst, &[])
}

pub fn hash_to_ecp2(msg: &[u8], dst: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(msg, dst, &[])
}
