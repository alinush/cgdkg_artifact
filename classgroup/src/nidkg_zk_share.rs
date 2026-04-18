//! ZK proof of correct sharing for the class-group PVSS.

use std::ffi::c_ulong;

use blstrs::{G1Projective, Scalar};
use cpp_core::{MutRef, Ref};
use group::Group;
use rand_core::RngCore;

use bicycl::b_i_c_y_c_l::{CLHSMqk, Mpz, QFI, RandGen};
use bicycl::{CiphertextBox, MpzBox, PublicKeyBox, QFIBox, VectorOfMpz, VectorOfQFI};

use crate::constants::{LAMBDA_BITS, LAMBDA_ST_BITS};
use crate::random_oracle::{
    random_oracle_to_ecp, random_oracle_to_scalar, HashedMap, UniqueHash,
};
use crate::scalar_bls12381::{field_add_assign, field_mul, field_mul_assign, rand_scalar, scalar_from_isize, scalar_zero};
use crate::utils::scalar_to_mpz;

/// Domain separators for the ZK proof of sharing.
const DOMAIN_PROOF_OF_SHARING_INSTANCE: &str = "crypto-cgdkg-zk-proof-of-sharing-instance";
const DOMAIN_PROOF_OF_SHARING_CHALLENGE: &str = "crypto-cgdkg-zk-proof-of-sharing-challenge";
const DOMAIN_CGDKG_ZK_SHARE_G: &str = "crypto-cgdkg-zk-proof-of-sharing-g";

pub fn get_cgdkg_zk_share_g(dkg_id: &dyn UniqueHash) -> G1Projective {
    random_oracle_to_ecp(DOMAIN_CGDKG_ZK_SHARE_G, dkg_id)
}

/// Instance = (g_1, g, [y_1..y_n], [A_0..A_{t-1}], R, [C_1..C_n])
pub struct SharingInstance {
    pub g1_gen: G1Projective,
    pub g: G1Projective,
    pub public_keys: Vec<PublicKeyBox>,
    pub public_coefficients: Vec<G1Projective>,
    pub randomizer: QFIBox,
    pub ciphertexts: Vec<CiphertextBox>,
}

pub struct SharingWitness {
    pub scalar_r: MpzBox,
    pub scalars_m: Vec<Scalar>,
}

#[derive(Clone, Debug)]
pub struct ZkProofSharing {
    pub ff: QFIBox,
    pub aa: G1Projective,
    pub yy: QFIBox,
    pub z_r: MpzBox,
    pub z_alpha: Scalar,
}

struct FirstMoveSharing {
    pub ff: QFIBox,
    pub aa: G1Projective,
    pub yy: QFIBox,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofSharingError {
    InvalidProof,
    InvalidInstance,
}

impl UniqueHash for SharingInstance {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("g1-generator", &self.g1_gen);
        map.insert_hashed("g-value", &self.g);
        map.insert_hashed("public-keys", &self.public_keys);
        map.insert_hashed("public-coefficients", &self.public_coefficients);
        map.insert_hashed("randomizer", &self.randomizer);
        map.insert_hashed("ciphertext", &self.ciphertexts);
        map.unique_hash()
    }
}

impl SharingInstance {
    pub fn hash_to_scalar(&self) -> Scalar {
        random_oracle_to_scalar(DOMAIN_PROOF_OF_SHARING_INSTANCE, self)
    }

    pub fn check_instance(&self) -> Result<(), ZkProofSharingError> {
        if self.public_keys.is_empty() || self.public_coefficients.is_empty() {
            return Err(ZkProofSharingError::InvalidInstance);
        }
        if self.public_keys.len() != self.ciphertexts.len() {
            return Err(ZkProofSharingError::InvalidInstance);
        }
        Ok(())
    }
}

impl UniqueHash for FirstMoveSharing {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("ff", &self.ff);
        map.insert_hashed("aa", &self.aa);
        map.insert_hashed("yy", &self.yy);
        map.unique_hash()
    }
}

fn sharing_proof_challenge(hashed_instance: &Scalar, first_move: &FirstMoveSharing) -> Scalar {
    let mut map = HashedMap::new();
    map.insert_hashed("instance-hash", hashed_instance);
    map.insert_hashed("first-move", first_move);
    random_oracle_to_scalar(DOMAIN_PROOF_OF_SHARING_CHALLENGE, &map)
}

pub fn prove_sharing<R: RngCore>(
    instance: &SharingInstance,
    witness: &SharingWitness,
    c: &CLHSMqk,
    rng: &mut R,
    rng_cpp: &mut RandGen,
) -> ZkProofSharing {
    instance
        .check_instance()
        .expect("The sharing proof instance is invalid");

    // x = oracle(instance)
    let x = instance.hash_to_scalar();

    // First move.
    let alpha = rand_scalar(rng);
    let rho = unsafe {
        rng_cpp.random_mpz_2exp(
            (c.encrypt_randomness_bound().nbits() + LAMBDA_BITS + LAMBDA_ST_BITS) as c_ulong,
        )
    };
    let ref_rho: Ref<Mpz> = unsafe { Ref::from_raw_ref(&rho) };
    let alpha_mpz = unsafe { scalar_to_mpz(&alpha) };

    // F = h^rho, A = g^alpha.
    let mut ff = unsafe { QFI::new_0a() };
    let mutref_ff: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut ff) };
    unsafe { c.power_of_h(mutref_ff, ref_rho) };
    let aa = instance.g * alpha;

    // x^1..x^n
    let n = instance.public_keys.len();
    let mut x_pows = Vec::with_capacity(n);
    x_pows.push(x);
    for i in 1..n {
        let mut p = x_pows[i - 1];
        field_mul_assign(&mut p, &x);
        x_pows.push(p);
    }

    // x_pows as Mpz for class-group mult_exp.
    let mut x_pows_mpz = unsafe { VectorOfMpz::new() };
    for xp in &x_pows {
        let xp_mpz = unsafe { scalar_to_mpz(xp) };
        let ref_xp: Ref<Mpz> = unsafe { Ref::from_raw_ref(&xp_mpz) };
        unsafe { x_pows_mpz.push_back(ref_xp) };
    }
    let ref_x_pows_mpz: Ref<VectorOfMpz> = unsafe { Ref::from_raw_ref(&x_pows_mpz) };

    // acc_pk = Π y_i^{x^i}
    let mut pks_qfi = unsafe { VectorOfQFI::new() };
    for pk in &instance.public_keys {
        unsafe { pks_qfi.push_back(pk.0.elt()) };
    }
    let ref_pks_qfi: Ref<VectorOfQFI> = unsafe { Ref::from_raw_ref(&pks_qfi) };
    let mut acc_pk = unsafe { QFI::new_0a() };
    let mutref_acc_pk: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut acc_pk) };
    unsafe { c.cl_g().mult_exp(mutref_acc_pk, ref_pks_qfi, ref_x_pows_mpz) };

    let ref_alpha_mpz: Ref<Mpz> = unsafe { Ref::from_raw_ref(&alpha_mpz) };
    let f_aa = unsafe { c.power_of_f(ref_alpha_mpz) };
    let ref_f_aa: Ref<QFI> = unsafe { Ref::from_raw_ref(&f_aa) };

    let mut yy = unsafe { QFI::new_0a() };
    let mutref_yy: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut yy) };
    unsafe { c.cl_g().nupow_3a(mutref_yy, mutref_acc_pk, ref_rho) };
    unsafe { c.cl_delta().nucomp(mutref_yy, mutref_yy, ref_f_aa) };

    let first_move = FirstMoveSharing {
        ff: QFIBox(ff),
        aa: aa.clone(),
        yy: QFIBox(yy),
    };

    // Challenge.
    let x_challenge = sharing_proof_challenge(&x, &first_move);
    let x_challenge_mpz = unsafe { scalar_to_mpz(&x_challenge) };
    let ref_x_challenge_mpz: Ref<Mpz> = unsafe { Ref::from_raw_ref(&x_challenge_mpz) };

    // Response.
    // z_r = r * x' + rho (computed over the integers via GMP).
    let mut z_r = unsafe { Mpz::new() };
    let mutref_z_r: MutRef<Mpz> = unsafe { MutRef::from_raw_ref(&mut z_r) };
    let ref_r: Ref<Mpz> = unsafe { Ref::from_raw_ref(&witness.scalar_r.0) };
    unsafe { Mpz::mul_mpz2_mpz(mutref_z_r, ref_r, ref_x_challenge_mpz) };
    unsafe { Mpz::add_mpz2_mpz(mutref_z_r, mutref_z_r, ref_rho) };

    // z_alpha = x' * Σ s_i x^i + alpha (in the scalar field).
    let mut z_alpha = field_mul(&witness.scalars_m[0], &x_pows[0]);
    for i in 1..n {
        let t = field_mul(&witness.scalars_m[i], &x_pows[i]);
        field_add_assign(&mut z_alpha, &t);
    }
    field_mul_assign(&mut z_alpha, &x_challenge);
    field_add_assign(&mut z_alpha, &alpha);

    ZkProofSharing {
        ff: first_move.ff.clone(),
        aa,
        yy: first_move.yy.clone(),
        z_r: MpzBox(z_r),
        z_alpha,
    }
}

pub fn verify_sharing(
    instance: &SharingInstance,
    nizk: &ZkProofSharing,
    c: &CLHSMqk,
) -> Result<(), ZkProofSharingError> {
    instance.check_instance()?;

    let n = instance.public_keys.len();
    let t = instance.public_coefficients.len();

    let x = instance.hash_to_scalar();

    let ref_ff: Ref<QFI> = unsafe { Ref::from_raw_ref(&nizk.ff.0) };
    let ref_yy: Ref<QFI> = unsafe { Ref::from_raw_ref(&nizk.yy.0) };

    let first_move = FirstMoveSharing {
        ff: nizk.ff.clone(),
        aa: nizk.aa.clone(),
        yy: nizk.yy.clone(),
    };

    let x_challenge = sharing_proof_challenge(&x, &first_move);
    let x_challenge_mpz = unsafe { scalar_to_mpz(&x_challenge) };
    let ref_x_challenge_mpz: Ref<Mpz> = unsafe { Ref::from_raw_ref(&x_challenge_mpz) };

    // x^1..x^n
    let mut x_pows = Vec::with_capacity(n);
    x_pows.push(x);
    for i in 1..n {
        let mut p = x_pows[i - 1];
        field_mul_assign(&mut p, &x);
        x_pows.push(p);
    }

    let mut x_pows_mpz = unsafe { VectorOfMpz::new() };
    for xp in &x_pows {
        let xp_mpz = unsafe { scalar_to_mpz(xp) };
        let ref_xp: Ref<Mpz> = unsafe { Ref::from_raw_ref(&xp_mpz) };
        unsafe { x_pows_mpz.push_back(ref_xp) };
    }
    let ref_xpows_mpz: Ref<VectorOfMpz> = unsafe { Ref::from_raw_ref(&x_pows_mpz) };

    // Eq 1: R^{x'} * F == h^{z_r}   (class group)
    let mut lhs_first = unsafe { QFI::new_0a() };
    let mutref_lhs_first: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut lhs_first) };
    let ref_randomizer: Ref<QFI> = unsafe { Ref::from_raw_ref(&instance.randomizer.0) };
    unsafe { c.cl_g().nupow_3a(mutref_lhs_first, ref_randomizer, ref_x_challenge_mpz) };
    unsafe { c.cl_delta().nucomp(mutref_lhs_first, mutref_lhs_first, ref_ff) };

    let mut rhs_first = unsafe { QFI::new_0a() };
    let mutref_rhs_first: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut rhs_first) };
    let ref_rhs_first: Ref<QFI> = unsafe { Ref::from_raw_ref(&rhs_first) };
    let ref_z_r: Ref<Mpz> = unsafe { Ref::from_raw_ref(&nizk.z_r.0) };
    unsafe { c.power_of_h(mutref_rhs_first, ref_z_r) };

    if !(lhs_first == ref_rhs_first) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Eq 2: Π_k A_k^{Σ_i i^k x^i})^{x'} * A == g^{z_alpha}   (G1)
    let mut i_vec: Vec<Scalar> = Vec::with_capacity(n);
    for i in 0..n {
        i_vec.push(scalar_from_isize((i + 1) as isize));
    }

    let mut i_x_pow_vec: Vec<Scalar> = x_pows.clone();

    let mut accs: Vec<Scalar> = Vec::with_capacity(t);
    let mut acc = scalar_zero();
    for val in &i_x_pow_vec {
        field_add_assign(&mut acc, val);
    }
    accs.push(acc);

    for _ in 1..t {
        let mut acc_k = scalar_zero();
        for j in 0..n {
            field_mul_assign(&mut i_x_pow_vec[j], &i_vec[j]);
            field_add_assign(&mut acc_k, &i_x_pow_vec[j]);
        }
        accs.push(acc_k);
    }

    // MSM: Σ_k accs[k] * A_k  — t terms.
    let mut lhs = G1Projective::multi_exp(&instance.public_coefficients, &accs);
    lhs = lhs * x_challenge;
    lhs = lhs + nizk.aa;

    let rhs = instance.g * nizk.z_alpha;
    if lhs != rhs {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Eq 3: (Π C_i^{x^i})^{x'} * Y == (Π y_i^{x^i})^{z_r} * f^{z_alpha}  (class group)
    let mut ciphers = unsafe { VectorOfQFI::new() };
    for i in 0..n {
        unsafe { ciphers.push_back(instance.ciphertexts[i].0.c2()) };
    }
    let ref_ciphers: Ref<VectorOfQFI> = unsafe { Ref::from_raw_ref(&ciphers) };

    let mut lhs_qfi = unsafe { QFI::new_0a() };
    let mut rhs_qfi = unsafe { QFI::new_0a() };
    let mutref_lhs: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut lhs_qfi) };
    let mutref_rhs: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut rhs_qfi) };
    let ref_rhs: Ref<QFI> = unsafe { Ref::from_raw_ref(&rhs_qfi) };
    unsafe { c.cl_g().mult_exp(mutref_lhs, ref_ciphers, ref_xpows_mpz) };
    unsafe { c.cl_g().nupow_3a(mutref_lhs, mutref_lhs, ref_x_challenge_mpz) };
    unsafe { c.cl_delta().nucomp(mutref_lhs, mutref_lhs, ref_yy) };

    let mut pks = unsafe { VectorOfQFI::new() };
    for i in 0..n {
        unsafe { pks.push_back(instance.public_keys[i].0.elt()) };
    }
    let ref_pks: Ref<VectorOfQFI> = unsafe { Ref::from_raw_ref(&pks) };

    unsafe { c.cl_g().mult_exp(mutref_rhs, ref_pks, ref_xpows_mpz) };

    let z_alpha_mpz = unsafe { scalar_to_mpz(&nizk.z_alpha) };
    let ref_z_alpha_mpz: Ref<Mpz> = unsafe { Ref::from_raw_ref(&z_alpha_mpz) };
    let f_z_alpha = unsafe { c.power_of_f(ref_z_alpha_mpz) };
    let ref_f_z_alpha: Ref<QFI> = unsafe { Ref::from_raw_ref(&f_z_alpha) };
    let ref_z_r: Ref<Mpz> = unsafe { Ref::from_raw_ref(&nizk.z_r.0) };
    unsafe { c.cl_g().nupow_3a(mutref_rhs, mutref_rhs, ref_z_r) };
    unsafe { c.cl_delta().nucomp(mutref_rhs, mutref_rhs, ref_f_z_alpha) };

    if !(lhs_qfi == ref_rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    Ok(())
}
