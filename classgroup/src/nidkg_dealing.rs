//! PVSS dealing struct + helpers used by the DKG aggregation code.

use blstrs::{G1Projective, Scalar};
use cpp_core::CppBox;
use std::ops::DerefMut;

use bicycl::b_i_c_y_c_l::CLHSMqk;
use bicycl::{CiphertextBox, SecretKeyBox};

use crate::cg_encryption::decrypt;
use crate::errors::{InternalError, InvalidArgumentError, MalformedPublicKeyError};
use crate::nidkg_zk_share::{get_cgdkg_zk_share_g, ZkProofSharing};
use crate::polynomial::Polynomial;
use crate::public_coefficients::PublicCoefficients;
use crate::scalar_bls12381::{field_add_assign, field_mul, scalar_from_isize, scalar_one, scalar_zero};
use crate::utils::mpz_to_scalar;

const CG_DKG_STR: &str = "cgdkg";

#[derive(Clone, Debug)]
pub struct Dealing {
    pub public_coefficients: PublicCoefficients,
    pub ciphertexts: Vec<CiphertextBox>,
    pub zk_proof_correct_sharing: ZkProofSharing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NiDkgCreateDealingError {
    InvalidThresholdError(InvalidArgumentError),
    MisnumberedReceiverError {
        receiver_index: usize,
        number_of_receivers: usize,
    },
    MalformedFsPublicKeyError {
        receiver_index: usize,
        error: MalformedPublicKeyError,
    },
    InternalError(InternalError),
}

/// Evaluate the public polynomial at 1..=n to get partial public keys.
pub fn pubcoeff_to_pks(
    public_coefficients: &PublicCoefficients,
    total_nodes: usize,
) -> Vec<G1Projective> {
    let mut pks = Vec::with_capacity(total_nodes);
    let t = public_coefficients.coefficients.len();
    for i in 1..=total_nodes {
        let mut i_pows = Vec::with_capacity(t);
        i_pows.push(scalar_one());
        let i_scalar = scalar_from_isize(i as isize);
        if t >= 2 {
            i_pows.push(i_scalar);
        }
        for _ in 2..t {
            let last = *i_pows.last().unwrap();
            i_pows.push(field_mul(&last, &i_scalar));
        }
        let pki = G1Projective::multi_exp(&public_coefficients.coefficients, &i_pows);
        pks.push(pki);
    }
    pks
}

pub fn aggregate_dealings(
    c: &CppBox<CLHSMqk>,
    dealings: &Vec<Dealing>,
    cg_private_key: &SecretKeyBox,
    node_index: usize,
    total_nodes: usize,
) -> anyhow::Result<(Scalar, G1Projective, Vec<G1Projective>, PublicCoefficients)> {
    let mut accumulated_sk = scalar_zero();

    let mut accumulated_public_polynomial = PublicCoefficients::from_poly_g(
        &Polynomial::zero(),
        &get_cgdkg_zk_share_g(&CG_DKG_STR.to_string()),
    );

    for dealing in dealings {
        if accumulated_public_polynomial.coefficients.is_empty() {
            accumulated_public_polynomial = dealing.public_coefficients.clone();
        } else {
            accumulated_public_polynomial += dealing.public_coefficients.clone();
        }
    }

    let my_shares: anyhow::Result<Vec<Scalar>> = dealings
        .iter()
        .map(|x| {
            let mut dec = decrypt(c, cg_private_key, &x.ciphertexts[node_index]);
            let dec_s = unsafe { mpz_to_scalar(dec.0.deref_mut()) };
            Ok(dec_s)
        })
        .collect();

    for s in my_shares? {
        field_add_assign(&mut accumulated_sk, &s);
    }

    let partial_pks = pubcoeff_to_pks(&accumulated_public_polynomial, total_nodes);
    let committee_pk = accumulated_public_polynomial.coefficients[0];
    Ok((
        accumulated_sk,
        committee_pk,
        partial_pks,
        accumulated_public_polynomial,
    ))
}
