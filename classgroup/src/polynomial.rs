//! Univariate polynomials over the BLS12-381 scalar field.

use std::borrow::Borrow;
use std::{iter, ops};

use blstrs::Scalar;
use ff::Field;
use rand_core::RngCore;

use crate::scalar_bls12381::{
    field_add_assign, field_eq, field_inv, field_mul, field_mul_assign, field_neg, field_sub,
    rand_scalar, scalar_one, scalar_zero,
};

/// `coefficients[i] * x^i`.
#[derive(Clone, Debug)]
pub struct Polynomial {
    pub coefficients: Vec<Scalar>,
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        if self.coefficients.len() != other.coefficients.len() {
            return false;
        }
        self.coefficients
            .iter()
            .zip(&other.coefficients)
            .all(|(x, y)| field_eq(x, y))
    }
}

impl From<Vec<Scalar>> for Polynomial {
    fn from(coefficients: Vec<Scalar>) -> Self {
        let mut ans = Polynomial { coefficients };
        ans.remove_zeros();
        ans
    }
}

impl<B: Borrow<Polynomial>> ops::Add<B> for Polynomial {
    type Output = Polynomial;
    fn add(mut self, rhs: B) -> Polynomial {
        self += rhs;
        self
    }
}

impl<B: Borrow<Polynomial>> ops::AddAssign<B> for Polynomial {
    fn add_assign(&mut self, rhs: B) {
        let rhs_len = rhs.borrow().coefficients.len();
        if rhs_len > self.coefficients.len() {
            self.coefficients.resize(rhs_len, scalar_zero());
        }
        for (s, r) in self.coefficients.iter_mut().zip(&rhs.borrow().coefficients) {
            field_add_assign(s, r);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Polynomial>> ops::Mul<B> for &'a Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: B) -> Polynomial {
        let rhs = rhs.borrow();
        if rhs.is_zero() || self.is_zero() {
            return Polynomial::zero();
        }
        let n = self.coefficients.len() + rhs.coefficients.len() - 1;
        let mut out = vec![scalar_zero(); n];
        for (i, a) in self.coefficients.iter().enumerate() {
            for (j, b) in rhs.coefficients.iter().enumerate() {
                let t = field_mul(a, b);
                field_add_assign(&mut out[i + j], &t);
            }
        }
        Polynomial::from(out)
    }
}

impl<B: Borrow<Polynomial>> ops::Mul<B> for Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: B) -> Polynomial {
        &self * rhs
    }
}

impl<B: Borrow<Self>> ops::MulAssign<B> for Polynomial {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl ops::MulAssign<Scalar> for Polynomial {
    fn mul_assign(&mut self, rhs: Scalar) {
        if bool::from(rhs.is_zero_vartime()) {
            self.coefficients.clear();
        } else {
            for c in &mut self.coefficients {
                field_mul_assign(c, &rhs);
            }
        }
    }
}

impl Polynomial {
    pub fn zero() -> Self {
        Polynomial { coefficients: vec![] }
    }

    pub fn random<R: RngCore>(number_of_coefficients: usize, rng: &mut R) -> Self {
        let coefficients: Vec<_> = iter::repeat(())
            .map(|()| rand_scalar(rng))
            .take(number_of_coefficients)
            .collect();
        Polynomial::from(coefficients)
    }

    pub fn constant(c: Scalar) -> Self {
        Polynomial::from(vec![c])
    }

    pub fn remove_zeros(&mut self) {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| bool::from(c.is_zero_vartime()))
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len);
    }

    pub fn is_zero(&self) -> bool {
        self.coefficients
            .iter()
            .all(|c| bool::from(c.is_zero_vartime()))
    }

    /// Horner's method.
    pub fn evaluate_at(&self, x: &Scalar) -> Scalar {
        let mut it = self.coefficients.iter().rev();
        match it.next() {
            None => scalar_zero(),
            Some(first) => {
                let mut ans = *first;
                for c in it {
                    field_mul_assign(&mut ans, x);
                    field_add_assign(&mut ans, c);
                }
                ans
            }
        }
    }

    pub fn interpolate(samples: &[(Scalar, Scalar)]) -> Self {
        if samples.is_empty() {
            return Polynomial::zero();
        }
        let mut poly = Polynomial::constant(samples[0].1);
        let minus_s0 = field_neg(&samples[0].0);
        let mut base = Polynomial::from(vec![minus_s0, scalar_one()]);

        for (x, y) in &samples[1..] {
            let mut diff = field_sub(y, &poly.evaluate_at(x));
            if let Some(inv) = field_inv(&base.evaluate_at(x)) {
                field_mul_assign(&mut diff, &inv);
                base *= diff;
                poly += &base;
                let minus_x = field_neg(x);
                base *= Polynomial::from(vec![minus_x, scalar_one()]);
            }
        }
        poly
    }
}
