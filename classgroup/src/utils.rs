//! Bridge helpers between blstrs `Scalar` and bicycl `Mpz`, plus the default
//! CL-HSM group constructor.

use std::ops::Deref;

use bicycl::b_i_c_y_c_l::{CLHSMqk, Mpz};
use bicycl::{cpp_vec_to_rust, rust_vec_to_cpp};
use cpp_std::VectorOfUchar;

use blstrs::Scalar;

use crate::constants::{P_VEC, Q_VEC};
use crate::scalar_bls12381::{scalar_from_bytes_be, scalar_to_bytes_be};

/// Byte-width used when marshalling a Scalar into an Mpz via bicycl's
/// `BIG_bytes_to_mpz`. We pad to 32 bytes, matching `Scalar`'s canonical size.
const SCALAR_BE_SIZE: usize = 32;

/// Convert a Scalar into an Mpz (big-endian byte marshalling through bicycl).
pub unsafe fn scalar_to_mpz(s: &Scalar) -> cpp_core::CppBox<Mpz> {
    let buffer: Vec<u8> = scalar_to_bytes_be(s).to_vec();
    let buffer_cpp = rust_vec_to_cpp(buffer);
    let ref_buffer: cpp_core::Ref<VectorOfUchar> = cpp_core::Ref::from_raw_ref(&buffer_cpp);
    let mut result = Mpz::new();
    result.b_i_g_bytes_to_mpz(ref_buffer);
    result
}

/// Convert an Mpz (as produced by `scalar_to_mpz`, or as decrypted by CL-HSM)
/// back into a Scalar. Assumes the Mpz fits in 32 bytes (i.e. represents a
/// value less than the BLS12-381 curve order).
pub unsafe fn mpz_to_scalar(m: &mut Mpz) -> Scalar {
    let big_bytes = m.mpz_to_b_i_g_bytes();
    let bytes = cpp_vec_to_rust(big_bytes.deref());

    // Left-pad with zeros to SCALAR_BE_SIZE bytes.
    let mut padded = [0u8; SCALAR_BE_SIZE];
    if bytes.len() <= SCALAR_BE_SIZE {
        let start = SCALAR_BE_SIZE - bytes.len();
        padded[start..].copy_from_slice(&bytes);
    } else {
        // The Mpz is larger than 32 bytes; take the low-order 32 bytes
        // (big-endian = the trailing bytes). This shouldn't happen for valid
        // shares, but keeps us robust.
        let start = bytes.len() - SCALAR_BE_SIZE;
        padded.copy_from_slice(&bytes[start..]);
    }

    scalar_from_bytes_be(&padded).unwrap_or_else(Scalar::default)
}

pub fn get_cl() -> cpp_core::CppBox<CLHSMqk> {
    let p_cpp = unsafe { rust_vec_to_cpp(P_VEC.to_vec()) };
    let q_cpp = unsafe { rust_vec_to_cpp(Q_VEC.to_vec()) };
    let ref_p: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&p_cpp) };
    let ref_q: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&q_cpp) };
    let p_mpz = unsafe { Mpz::from_vector_of_uchar(ref_p) };
    let q_mpz = unsafe { Mpz::from_vector_of_uchar(ref_q) };
    let ref_p_mpz: cpp_core::Ref<Mpz> = unsafe { cpp_core::Ref::from_raw_ref(&p_mpz) };
    let ref_q_mpz: cpp_core::Ref<Mpz> = unsafe { cpp_core::Ref::from_raw_ref(&q_mpz) };
    unsafe { CLHSMqk::from_mpz_usize_mpz(ref_q_mpz, 1, ref_p_mpz) }
}

/// Convert a Scalar into a bicycl `Mpz` using the big-endian marshalling.
/// (Kept for call sites that use the old `big_to_mpz` name.)
#[allow(dead_code)]
pub unsafe fn big_to_mpz(s: Scalar) -> cpp_core::CppBox<Mpz> {
    scalar_to_mpz(&s)
}

/// Legacy name, identical to `mpz_to_scalar`.
#[allow(dead_code)]
pub unsafe fn mpz_to_big(m: &mut Mpz) -> Scalar {
    mpz_to_scalar(m)
}
