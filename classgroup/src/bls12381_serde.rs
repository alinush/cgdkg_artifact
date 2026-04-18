//! Byte-level (de)serialization for BLS12-381 scalars and G1/G2 points.
//!
//! Backed by blstrs's native compressed serialization.

use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::{Curve, GroupEncoding};

use crate::scalar_bls12381::{scalar_from_bytes_be, scalar_to_bytes_be};

pub const FR_SIZE: usize = 32;
pub const ECP_SIZE: usize = 48;
pub const ECP2_SIZE: usize = 96;

pub fn fr_to_bytes(s: &Scalar) -> [u8; FR_SIZE] {
    scalar_to_bytes_be(s)
}

pub fn fr_from_bytes(bytes: &[u8; FR_SIZE]) -> Result<Scalar, ()> {
    scalar_from_bytes_be(bytes).ok_or(())
}

pub fn ecp_to_bytes(p: &G1Projective) -> [u8; ECP_SIZE] {
    p.to_affine().to_compressed()
}

pub fn ecp_from_bytes(bytes: &[u8; ECP_SIZE]) -> Result<G1Projective, ()> {
    let ct = G1Affine::from_compressed(bytes);
    if ct.is_some().into() {
        Ok(G1Projective::from(ct.unwrap()))
    } else {
        Err(())
    }
}

#[allow(dead_code)]
pub fn ecp2_to_bytes(p: &G2Projective) -> [u8; ECP2_SIZE] {
    p.to_affine().to_compressed()
}

#[allow(dead_code)]
pub fn ecp2_from_bytes(bytes: &[u8; ECP2_SIZE]) -> Result<G2Projective, ()> {
    let ct = G2Affine::from_compressed(bytes);
    if ct.is_some().into() {
        Ok(G2Projective::from(ct.unwrap()))
    } else {
        Err(())
    }
}

/// Fixed-width big-endian serialization of a G1 point, as a `Vec<u8>` wrapper.
pub fn ecp_to_vec(p: &G1Projective) -> Vec<u8> {
    ecp_to_bytes(p).to_vec()
}

/// Used by the bicycl hashing helpers — same bytes as `ecp_to_bytes`, just
/// returned as a `[u8; 32]` (scalar-sized) digest input slice. We keep the
/// function present for backwards compatibility with other files.
#[allow(dead_code)]
pub fn fr_to_vec(s: &Scalar) -> Vec<u8> {
    fr_to_bytes(s).to_vec()
}

/// Convert a 32-byte hash into a Scalar, shaving two MSBs to land below the
/// curve order. Kept for compat with the old `convert_hash256_to_scalar`.
pub fn convert_hash256_to_scalar(hash_vec: &mut Vec<u8>) -> Scalar {
    assert_eq!(hash_vec.len(), 32);
    // Shave 2 MSBs so the big-endian value is < curve_order with probability 1.
    hash_vec[0] &= 0xff >> 2;
    let mut buf = [0u8; 32];
    buf.copy_from_slice(hash_vec);
    scalar_from_bytes_be(&buf).unwrap_or_else(Scalar::default)
}
