//! Public polynomial commitments: `A_k = g^{a_k}` for each coefficient.

use std::borrow::Borrow;
use std::ops;

use blstrs::{G1Projective, Scalar};
use group::Group;

use crate::polynomial::Polynomial;

#[derive(Clone, Debug)]
pub struct PublicCoefficients {
    pub g: G1Projective,
    pub coefficients: Vec<G1Projective>,
}

impl PartialEq for PublicCoefficients {
    fn eq(&self, other: &Self) -> bool {
        if self.g != other.g {
            return false;
        }
        if self.coefficients.len() != other.coefficients.len() {
            return false;
        }
        self.coefficients
            .iter()
            .zip(&other.coefficients)
            .all(|(x, y)| x == y)
    }
}

impl<B: Borrow<PublicCoefficients>> ops::AddAssign<B> for PublicCoefficients {
    fn add_assign(&mut self, rhs: B) {
        let r = rhs.borrow();
        assert!(self.g == r.g);
        let rhs_len = r.coefficients.len();
        if rhs_len > self.coefficients.len() {
            self.coefficients.resize(rhs_len, self.g);
        }
        for (s, o) in self.coefficients.iter_mut().zip(&r.coefficients) {
            *s = *s + o;
        }
        self.remove_zeros();
    }
}

impl<B: Borrow<PublicCoefficients>> ops::Add<B> for PublicCoefficients {
    type Output = Self;
    fn add(mut self, rhs: B) -> Self {
        self += rhs;
        self
    }
}

impl<B: Borrow<Scalar>> ops::MulAssign<B> for PublicCoefficients {
    fn mul_assign(&mut self, rhs: B) {
        let s = rhs.borrow();
        for c in &mut self.coefficients {
            *c = *c * s;
        }
    }
}

impl<B: Borrow<Scalar>> ops::Mul<B> for PublicCoefficients {
    type Output = Self;
    fn mul(mut self, rhs: B) -> Self {
        self *= rhs;
        self
    }
}

impl PublicCoefficients {
    pub fn from_poly_g(polynomial: &Polynomial, g: &G1Projective) -> Self {
        PublicCoefficients {
            g: *g,
            coefficients: polynomial
                .coefficients
                .iter()
                .map(|x| g * x)
                .collect(),
        }
    }

    pub fn remove_zeros(&mut self) {
        // We treat a "zero" coefficient as the identity element of G1 — but in
        // the additive notation that's the identity, not `g`. The legacy code
        // used `g` as the stand-in sentinel; to preserve semantics we follow
        // the identity convention here, which is what the NIZK expects.
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| bool::from(c.is_identity()))
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len);
    }

    /// Evaluate public coefficients at `x` (in G1).
    pub fn evaluate_at(&self, x: &Scalar) -> G1Projective {
        let mut it = self.coefficients.iter().rev();
        match it.next() {
            None => self.g,
            Some(first) => {
                let mut ans = *first;
                for c in it {
                    ans = ans * x;
                    ans = ans + c;
                }
                ans
            }
        }
    }
}
