//! A self-contained PVSS (publicly-verifiable secret sharing) abstraction over
//! the class-group NI-VSS, with BLS12-381 side implemented via `blstrs`.

use std::convert::TryInto;
use std::io::Read;
use std::ops::DerefMut;

use blstrs::{G1Projective, Scalar};
use cpp_core::{CppBox, MutRef, Ref};
use group::Group;
use rand_core::RngCore;

use bicycl::b_i_c_y_c_l::{CLHSMqk, Mpz, QFI, RandGen};
use bicycl::{CiphertextBox, MpzBox, PublicKeyBox, QFIBox, SecretKeyBox};

use crate::bls12381_serde::{
    ecp_from_bytes, ecp_to_bytes, fr_from_bytes, fr_to_bytes, ECP_SIZE, FR_SIZE,
};
use crate::cg_encryption::{decrypt, encrypt_all, keygen as cg_keygen};
use crate::key_pop_zk::PopZk;
use crate::nidkg_dealing::Dealing;
use crate::nidkg_zk_share::{
    get_cgdkg_zk_share_g, prove_sharing, verify_sharing, SharingInstance, SharingWitness,
    ZkProofSharing,
};
use crate::polynomial::Polynomial;
use crate::public_coefficients::PublicCoefficients;
use crate::scalar_bls12381::scalar_from_isize;
use crate::utils::mpz_to_scalar;

pub const DEFAULT_DST: &str = "cgdkg";

pub struct PvssParams {
    pub c: CppBox<CLHSMqk>,
    pub g: G1Projective,
    pub dst: String,
}

impl PvssParams {
    pub fn new(dst: &str) -> Self {
        PvssParams {
            c: crate::utils::get_cl(),
            g: get_cgdkg_zk_share_g(&dst.to_string()),
            dst: dst.to_string(),
        }
    }
}

pub fn keygen(
    params: &PvssParams,
    rng_cpp: &mut CppBox<RandGen>,
    associated_data: &Vec<u8>,
) -> (SecretKeyBox, PublicKeyBox, PopZk) {
    cg_keygen(&params.c, rng_cpp, associated_data)
}

#[derive(Clone, Debug)]
pub struct Transcript {
    pub public_coefficients: Vec<G1Projective>,
    pub ciphertexts: Vec<CiphertextBox>,
    pub proof: ZkProofSharing,
}

pub struct DealtShares {
    pub polynomial: Polynomial,
    /// `shares[i] = f(i+1)`
    pub shares: Vec<Scalar>,
}

impl DealtShares {
    pub fn secret(&self) -> Scalar {
        self.polynomial
            .coefficients
            .first()
            .copied()
            .unwrap_or_default()
    }
}

pub fn deal<R: RngCore>(
    params: &PvssParams,
    pks: &[PublicKeyBox],
    threshold: usize,
    rng: &mut R,
    rng_cpp: &mut CppBox<RandGen>,
) -> (Transcript, DealtShares) {
    assert!(threshold >= 1, "threshold must be >= 1");
    assert!(pks.len() >= threshold, "n must be >= threshold");

    let poly = Polynomial::random(threshold, rng);
    let transcript = deal_with_poly(params, pks, &poly, rng, rng_cpp);

    let shares: Vec<Scalar> = (0..pks.len())
        .map(|j| poly.evaluate_at(&scalar_from_isize((j + 1) as isize)))
        .collect();
    (transcript, DealtShares { polynomial: poly, shares })
}

pub fn deal_with_poly<R: RngCore>(
    params: &PvssParams,
    pks: &[PublicKeyBox],
    poly: &Polynomial,
    rng: &mut R,
    rng_cpp: &mut CppBox<RandGen>,
) -> Transcript {
    let n = pks.len();
    let pubpoly = PublicCoefficients::from_poly_g(poly, &params.g);

    let evaluations: Vec<Scalar> = (0..n)
        .map(|j| poly.evaluate_at(&scalar_from_isize((j + 1) as isize)))
        .collect();

    let (ciphers, r) = encrypt_all(&params.c, rng_cpp, &pks.to_vec(), evaluations.clone());

    // randomizer R = h^r, which is also the shared c1 of every ciphertext.
    let mut g_r = unsafe { QFI::new_0a() };
    let ref_r: Ref<Mpz> = unsafe { Ref::from_raw_ref(&r.0) };
    let mutref_g_r: MutRef<QFI> = unsafe { MutRef::from_raw_ref(&mut g_r) };
    unsafe { params.c.power_of_h(mutref_g_r, ref_r) };

    let instance = SharingInstance {
        g1_gen: G1Projective::generator(),
        g: params.g,
        public_keys: pks.to_vec(),
        public_coefficients: pubpoly.coefficients.clone(),
        randomizer: QFIBox(g_r),
        ciphertexts: ciphers.clone(),
    };
    let witness = SharingWitness { scalar_r: r, scalars_m: evaluations };
    let proof = prove_sharing(&instance, &witness, &params.c, rng, rng_cpp);

    Transcript {
        public_coefficients: pubpoly.coefficients,
        ciphertexts: ciphers,
        proof,
    }
}

pub fn verify(params: &PvssParams, pks: &[PublicKeyBox], t: &Transcript) -> bool {
    if t.ciphertexts.is_empty() || t.ciphertexts.len() != pks.len() {
        return false;
    }
    let ffi_c1 = unsafe {
        bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
            cpp_core::CastInto::<Ref<QFI>>::cast_into(t.ciphertexts[0].0.c1()).as_raw_ptr(),
        )
    };
    let c1_cpp = unsafe { CppBox::from_raw(ffi_c1) }
        .expect("attempted to construct a null CppBox");

    let instance = SharingInstance {
        g1_gen: G1Projective::generator(),
        g: params.g,
        public_keys: pks.to_vec(),
        public_coefficients: t.public_coefficients.clone(),
        randomizer: QFIBox(c1_cpp),
        ciphertexts: t.ciphertexts.clone(),
    };

    verify_sharing(&instance, &t.proof, &params.c).is_ok()
}

pub fn decrypt_share(
    params: &PvssParams,
    i: usize,
    sk: &SecretKeyBox,
    t: &Transcript,
) -> Scalar {
    let mut dec = decrypt(&params.c, sk, &t.ciphertexts[i]);
    unsafe { mpz_to_scalar(dec.0.deref_mut()) }
}

impl Transcript {
    pub fn into_dealing(self, g: &G1Projective) -> Dealing {
        Dealing {
            public_coefficients: PublicCoefficients {
                g: *g,
                coefficients: self.public_coefficients,
            },
            ciphertexts: self.ciphertexts,
            zk_proof_correct_sharing: self.proof,
        }
    }

    pub fn from_dealing(d: Dealing) -> Self {
        Transcript {
            public_coefficients: d.public_coefficients.coefficients,
            ciphertexts: d.ciphertexts,
            proof: d.zk_proof_correct_sharing,
        }
    }
}

// --------------------------------------------------------------------------
//                               serialization
// --------------------------------------------------------------------------

fn put_len(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}

fn take_len(cur: &mut std::io::Cursor<&[u8]>) -> Option<usize> {
    let mut b = [0u8; 4];
    cur.read_exact(&mut b).ok()?;
    Some(u32::from_le_bytes(b) as usize)
}

fn take_exact(cur: &mut std::io::Cursor<&[u8]>, n: usize) -> Option<Vec<u8>> {
    let mut v = vec![0u8; n];
    cur.read_exact(&mut v).ok()?;
    Some(v)
}

impl Transcript {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        put_len(&mut out, self.public_coefficients.len());
        for a in &self.public_coefficients {
            out.extend_from_slice(&ecp_to_bytes(a));
        }

        put_len(&mut out, self.ciphertexts.len());
        for ct in &self.ciphertexts {
            let ct_bytes = unsafe { ct.to_bytes() };
            put_len(&mut out, ct_bytes.len());
            out.extend_from_slice(&ct_bytes);
        }

        let ff = unsafe { self.proof.ff.to_bytes() };
        put_len(&mut out, ff.len());
        out.extend_from_slice(&ff);

        out.extend_from_slice(&ecp_to_bytes(&self.proof.aa));

        let yy = unsafe { self.proof.yy.to_bytes() };
        put_len(&mut out, yy.len());
        out.extend_from_slice(&yy);

        let z_r = unsafe { self.proof.z_r.to_bytes() };
        put_len(&mut out, z_r.len());
        out.extend_from_slice(&z_r);

        out.extend_from_slice(&fr_to_bytes(&self.proof.z_alpha));

        out
    }

    pub fn from_bytes(bytes: &[u8], params: &PvssParams) -> Option<Transcript> {
        let mut cur = std::io::Cursor::new(bytes);

        let t = take_len(&mut cur)?;
        let mut public_coefficients = Vec::with_capacity(t);
        for _ in 0..t {
            let buf = take_exact(&mut cur, ECP_SIZE)?;
            let arr: [u8; ECP_SIZE] = buf.as_slice().try_into().ok()?;
            public_coefficients.push(ecp_from_bytes(&arr).ok()?);
        }

        let n = take_len(&mut cur)?;
        let mut ciphertexts = Vec::with_capacity(n);
        for _ in 0..n {
            let l = take_len(&mut cur)?;
            let ct_bytes = take_exact(&mut cur, l)?;
            let ct = unsafe { CiphertextBox::from_bytes(&ct_bytes, &params.c)? };
            ciphertexts.push(ct);
        }

        let l = take_len(&mut cur)?;
        let ff_bytes = take_exact(&mut cur, l)?;
        let ff = unsafe { QFIBox::from_bytes(&ff_bytes, &params.c)? };

        let aa_buf = take_exact(&mut cur, ECP_SIZE)?;
        let aa_arr: [u8; ECP_SIZE] = aa_buf.as_slice().try_into().ok()?;
        let aa = ecp_from_bytes(&aa_arr).ok()?;

        let l = take_len(&mut cur)?;
        let yy_bytes = take_exact(&mut cur, l)?;
        let yy = unsafe { QFIBox::from_bytes(&yy_bytes, &params.c)? };

        let l = take_len(&mut cur)?;
        let z_r_bytes = take_exact(&mut cur, l)?;
        let z_r = unsafe { MpzBox::from_bytes(&z_r_bytes)? };

        let za_buf = take_exact(&mut cur, FR_SIZE)?;
        let za_arr: [u8; FR_SIZE] = za_buf.as_slice().try_into().ok()?;
        let z_alpha = fr_from_bytes(&za_arr).ok()?;

        Some(Transcript {
            public_coefficients,
            ciphertexts,
            proof: ZkProofSharing { ff, aa, yy, z_r, z_alpha },
        })
    }
}

// --------------------------------------------------------------------------
//                                   tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod test {
    use super::*;
    use bicycl::b_i_c_y_c_l::Mpz;
    use bicycl::cpp_std::VectorOfUchar;
    use bicycl::rust_vec_to_cpp;
    use group::Group;

    use crate::polynomial::Polynomial;
    use crate::rng::RAND_ChaCha20;
    use crate::scalar_bls12381::field_eq;

    fn new_rngs(seed: [u8; 32]) -> (RAND_ChaCha20, CppBox<RandGen>) {
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: Ref<VectorOfUchar> = unsafe { Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: Ref<Mpz> = unsafe { Ref::from_raw_ref(&seed_mpz) };
        let rng = RAND_ChaCha20::new(seed);
        let rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };
        (rng, rng_cpp)
    }

    fn gen_keys(
        params: &PvssParams,
        rng_cpp: &mut CppBox<RandGen>,
        n: usize,
    ) -> (Vec<SecretKeyBox>, Vec<PublicKeyBox>) {
        let ad = Vec::new();
        let mut sks = Vec::with_capacity(n);
        let mut pks = Vec::with_capacity(n);
        for _ in 0..n {
            let (sk, pk, _pop) = keygen(params, rng_cpp, &ad);
            sks.push(sk);
            pks.push(pk);
        }
        (sks, pks)
    }

    #[test]
    fn deal_then_verify() {
        let (mut rng, mut rng_cpp) = new_rngs([7u8; 32]);
        let params = PvssParams::new(DEFAULT_DST);
        let (_sks, pks) = gen_keys(&params, &mut rng_cpp, 8);

        let (t, _) = deal(&params, &pks, 6, &mut rng, &mut rng_cpp);
        assert!(verify(&params, &pks, &t));
    }

    #[test]
    fn serialize_roundtrip_still_verifies() {
        let (mut rng, mut rng_cpp) = new_rngs([11u8; 32]);
        let params = PvssParams::new(DEFAULT_DST);
        let (_sks, pks) = gen_keys(&params, &mut rng_cpp, 10);

        let (orig, _) = deal(&params, &pks, 4, &mut rng, &mut rng_cpp);
        let bytes = orig.to_bytes();
        let round = Transcript::from_bytes(&bytes, &params).expect("deserialize");

        assert_eq!(bytes, round.to_bytes());
        assert!(verify(&params, &pks, &round));
    }

    #[test]
    fn decrypt_share_matches_dealt_share() {
        let (mut rng, mut rng_cpp) = new_rngs([19u8; 32]);
        let params = PvssParams::new(DEFAULT_DST);
        let n = 7;
        let threshold = 4;
        let (sks, pks) = gen_keys(&params, &mut rng_cpp, n);

        let (t, dealt) = deal(&params, &pks, threshold, &mut rng, &mut rng_cpp);
        assert!(verify(&params, &pks, &t));

        for i in 0..n {
            let got = decrypt_share(&params, i, &sks[i], &t);
            assert!(
                field_eq(&got, &dealt.shares[i]),
                "share mismatch at index {}",
                i
            );

            // g^share_i must equal A(i+1).
            let expected = params.g * dealt.shares[i];
            let public_evaluation = PublicCoefficients {
                g: params.g,
                coefficients: t.public_coefficients.clone(),
            }
            .evaluate_at(&scalar_from_isize((i + 1) as isize));
            assert_eq!(expected, public_evaluation);
        }
    }

    #[test]
    fn interpolation_recovers_secret() {
        let (mut rng, mut rng_cpp) = new_rngs([23u8; 32]);
        let params = PvssParams::new(DEFAULT_DST);
        let n = 9;
        let threshold = 5;
        let (sks, pks) = gen_keys(&params, &mut rng_cpp, n);

        let poly = Polynomial::random(threshold, &mut rng);
        let expected_secret = poly.coefficients[0];

        let t = deal_with_poly(&params, &pks, &poly, &mut rng, &mut rng_cpp);
        assert!(verify(&params, &pks, &t));

        let mut samples: Vec<(Scalar, Scalar)> = Vec::with_capacity(threshold);
        for i in 0..threshold {
            let s = decrypt_share(&params, i, &sks[i], &t);
            samples.push((scalar_from_isize((i + 1) as isize), s));
        }
        let recovered = Polynomial::interpolate(&samples);
        assert!(field_eq(&recovered.coefficients[0], &expected_secret));

        // Silence dead-code warning from unused import.
        let _ = G1Projective::identity();
    }
}
