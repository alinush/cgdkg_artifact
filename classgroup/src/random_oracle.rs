//! Random oracle / transcript hashing primitives.
//!
//! `UniqueHash` provides a canonical 32-byte digest for each crypto primitive
//! used in the Fiat–Shamir transforms. `random_oracle_to_scalar` and
//! `random_oracle_to_ecp` map a digest to a uniformly-random Scalar / G1 point.

use std::collections::BTreeMap;
use std::ops::Deref;

use blstrs::{G1Projective, G2Projective, Scalar};
use bicycl::cpp_std::VectorOfUchar;
use bicycl::{cpp_vec_to_rust, CiphertextBox, PublicKeyBox, QFIBox};
use sha2::{Digest, Sha256};

use crate::bls12381_serde::{ecp_to_bytes, ecp2_to_bytes, fr_to_bytes};
use crate::context::{Context, DomainSeparationContext};
use crate::hash_to_point::hash_to_ecp;

const DOMAIN_RO_INT: &str = "crypto-random-oracle-integer";
const DOMAIN_RO_STRING: &str = "crypto-random-oracle-string";
const DOMAIN_RO_BIG: &str = "crypto-random-oracle-bls12381-big";
const DOMAIN_RO_ECP_POINT: &str = "crypto-random-oracle-bls12381-g1";
const DOMAIN_RO_ECP2_POINT: &str = "crypto-random-oracle-bls12381-g2";
const DOMAIN_RO_BYTE_ARRAY: &str = "crypto-random-oracle-byte-array";
const DOMAIN_RO_MAP: &str = "crypto-random-oracle-map";
const DOMAIN_RO_VECTOR: &str = "crypto-random-oracle-vector";
const DOMAIN_RO_QFI: &str = "crypto-random-oracle-qfi";
const DOMAIN_RO_PUBLIC_KEY: &str = "crypto-random-oracle-public-key";
const DOMAIN_RO_CIPHERTEXT: &str = "crypto-random-oracle-ciphertext";

pub trait UniqueHash {
    fn unique_hash(&self) -> [u8; 32];
}

fn new_hasher_with_domain(domain: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(DomainSeparationContext::new(domain).as_bytes());
    hasher
}

fn finish(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl UniqueHash for String {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_STRING);
        h.update(self.as_bytes());
        finish(h)
    }
}

impl UniqueHash for usize {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_INT);
        h.update(self.to_be_bytes());
        finish(h)
    }
}

impl UniqueHash for Vec<u8> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_BYTE_ARRAY);
        h.update(self);
        finish(h)
    }
}

impl UniqueHash for Scalar {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_BIG);
        h.update(fr_to_bytes(self));
        finish(h)
    }
}

impl UniqueHash for G1Projective {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_ECP_POINT);
        h.update(ecp_to_bytes(self));
        finish(h)
    }
}

impl UniqueHash for G2Projective {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_ECP2_POINT);
        h.update(ecp2_to_bytes(self));
        finish(h)
    }
}

impl UniqueHash for QFIBox {
    fn unique_hash(&self) -> [u8; 32] {
        let mut a_bytes = unsafe { VectorOfUchar::new() };
        let mut b_bytes = unsafe { VectorOfUchar::new() };
        let mut c_bytes = unsafe { VectorOfUchar::new() };

        let mutref_a: cpp_core::MutRef<VectorOfUchar> =
            unsafe { cpp_core::MutRef::from_raw_ref(&mut a_bytes) };
        let mutref_b: cpp_core::MutRef<VectorOfUchar> =
            unsafe { cpp_core::MutRef::from_raw_ref(&mut b_bytes) };
        let mutref_c: cpp_core::MutRef<VectorOfUchar> =
            unsafe { cpp_core::MutRef::from_raw_ref(&mut c_bytes) };

        unsafe { self.0.a().mpz_to_vector(mutref_a) };
        unsafe { self.0.b().mpz_to_vector(mutref_b) };
        unsafe { self.0.c().mpz_to_vector(mutref_c) };

        let a_rust = unsafe { cpp_vec_to_rust(mutref_a.deref()) };
        let b_rust = unsafe { cpp_vec_to_rust(mutref_b.deref()) };
        let c_rust = unsafe { cpp_vec_to_rust(mutref_c.deref()) };

        let mut h = new_hasher_with_domain(DOMAIN_RO_QFI);
        h.update(&a_rust);
        h.update(&b_rust);
        h.update(&c_rust);
        finish(h)
    }
}

impl UniqueHash for PublicKeyBox {
    fn unique_hash(&self) -> [u8; 32] {
        let ffi_pk = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    self.0.elt(),
                )
                .as_raw_ptr(),
            )
        };
        let pk_qfi = unsafe { cpp_core::CppBox::from_raw(ffi_pk) }
            .expect("attempted to construct a null CppBox");

        let mut h = new_hasher_with_domain(DOMAIN_RO_PUBLIC_KEY);
        h.update(&QFIBox(pk_qfi).unique_hash());
        finish(h)
    }
}

impl UniqueHash for CiphertextBox {
    fn unique_hash(&self) -> [u8; 32] {
        let ffi_c1 = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    self.0.c1(),
                )
                .as_raw_ptr(),
            )
        };
        let c1_qfi = unsafe { cpp_core::CppBox::from_raw(ffi_c1) }
            .expect("attempted to construct a null CppBox");

        let ffi_c2 = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    self.0.c2(),
                )
                .as_raw_ptr(),
            )
        };
        let c2_qfi = unsafe { cpp_core::CppBox::from_raw(ffi_c2) }
            .expect("attempted to construct a null CppBox");

        let mut h = new_hasher_with_domain(DOMAIN_RO_CIPHERTEXT);
        h.update(&QFIBox(c1_qfi).unique_hash());
        h.update(&QFIBox(c2_qfi).unique_hash());
        finish(h)
    }
}

impl UniqueHash for Box<dyn UniqueHash> {
    fn unique_hash(&self) -> [u8; 32] {
        (**self).unique_hash()
    }
}

impl<T: UniqueHash> UniqueHash for Vec<T> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_VECTOR);
        for item in self {
            h.update(item.unique_hash());
        }
        finish(h)
    }
}

impl UniqueHash for Vec<&dyn UniqueHash> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_VECTOR);
        for item in self {
            h.update(item.unique_hash());
        }
        finish(h)
    }
}

pub struct HashedMap(pub BTreeMap<[u8; 32], [u8; 32]>);

impl Default for HashedMap {
    fn default() -> Self {
        Self::new()
    }
}

impl HashedMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert_hashed<S: ToString, T: UniqueHash>(
        &mut self,
        key: S,
        value: &T,
    ) -> Option<[u8; 32]> {
        self.0
            .insert(key.to_string().unique_hash(), value.unique_hash())
    }
}

impl UniqueHash for HashedMap {
    fn unique_hash(&self) -> [u8; 32] {
        let mut h = new_hasher_with_domain(DOMAIN_RO_MAP);
        for (k, v) in self.0.iter() {
            h.update(k);
            h.update(v);
        }
        finish(h)
    }
}

pub fn random_oracle(domain: &str, data: &dyn UniqueHash) -> [u8; 32] {
    let mut h = new_hasher_with_domain(domain);
    h.update(data.unique_hash());
    finish(h)
}

/// Hash `data` into a field element. We shave the two most significant bits of
/// the 32-byte digest so the result is in `[0, 2^254)`, which is below the
/// BLS12-381 scalar field order q. This yields a challenge with ~254 bits of
/// entropy — overkill for Fiat–Shamir at 128-bit security.
pub fn random_oracle_to_scalar(domain: &str, data: &dyn UniqueHash) -> Scalar {
    let mut digest = random_oracle(domain, data);
    digest[0] &= 0x3f;
    let ct = Scalar::from_bytes_be(&digest);
    if bool::from(ct.is_some()) {
        ct.unwrap()
    } else {
        // Unreachable given the shave above, but kept so we never panic.
        Scalar::default()
    }
}

pub fn random_oracle_to_ecp(domain: &str, data: &dyn UniqueHash) -> G1Projective {
    hash_to_ecp(
        &data.unique_hash(),
        DomainSeparationContext::new(domain).as_bytes(),
    )
}
