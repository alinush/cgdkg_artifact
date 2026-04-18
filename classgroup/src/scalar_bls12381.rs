//! BLS12-381 scalar-field helpers, backed by `blstrs::Scalar`.
//!
//! Keeps the `field_*` / `rand_scalar` / `scalar_*` API shape from the old
//! MIRACL-based version so the rest of the crate reads the same.

use blstrs::Scalar;
use ff::{Field, PrimeField};
use rand_core::RngCore;

pub fn rand_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    Scalar::random(&mut *rng)
}

pub fn field_mul(left: &Scalar, right: &Scalar) -> Scalar {
    left * right
}

pub fn field_mul_assign(left: &mut Scalar, right: &Scalar) {
    *left = *left * right;
}

pub fn field_add(left: &Scalar, right: &Scalar) -> Scalar {
    left + right
}

pub fn field_add_assign(left: &mut Scalar, right: &Scalar) {
    *left = *left + right;
}

pub fn field_double_assign(x: &mut Scalar) {
    *x = x.double();
}

pub fn field_neg(x: &Scalar) -> Scalar {
    -*x
}

pub fn field_sub(left: &Scalar, right: &Scalar) -> Scalar {
    left - right
}

#[allow(dead_code)]
pub fn field_sub_assign(left: &mut Scalar, right: &Scalar) {
    *left = *left - right;
}

pub fn field_eq(left: &Scalar, right: &Scalar) -> bool {
    left == right
}

pub fn field_inv(x: &Scalar) -> Option<Scalar> {
    let inv = x.invert();
    if inv.is_some().into() {
        Some(inv.unwrap())
    } else {
        None
    }
}

pub fn scalar_one() -> Scalar {
    Scalar::ONE
}

pub fn scalar_zero() -> Scalar {
    Scalar::ZERO
}

pub fn scalar_from_isize(x: isize) -> Scalar {
    if x < 0 {
        -Scalar::from((-x) as u64)
    } else {
        Scalar::from(x as u64)
    }
}

/// Serialize a scalar as 32 big-endian bytes (canonical).
pub fn scalar_to_bytes_be(s: &Scalar) -> [u8; 32] {
    let mut le = s.to_repr();
    le.as_mut().reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(le.as_ref());
    out
}

/// Parse a scalar from 32 big-endian bytes. Returns `None` if >= curve order.
pub fn scalar_from_bytes_be(bytes: &[u8; 32]) -> Option<Scalar> {
    let mut le = *bytes;
    le.reverse();
    let ct = Scalar::from_repr(le);
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}
