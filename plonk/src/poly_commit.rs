use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use ark_ff::UniformRand;
use ark_poly::univariate::DenseOrSparsePolynomial;
use ark_poly::{polynomial::univariate::DensePolynomial, EvaluationDomain};
use ark_poly::{DenseUVPolynomial, Polynomial, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer, One};
use rand::Rng;

#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PolyCk<E: Pairing> {
    pub powers_of_tau: Vec<E::G1Affine>, //We assume that we have eval version
}

impl<E: Pairing> PolyCk<E> {
    #[allow(unused)]
    pub fn new<R: Rng>(domain_size: usize, rng: &mut R) -> Self {
        // using dummy to speedup testing
        let mut powers_of_tau: Vec<E::G1Affine> = vec![E::G1Affine::rand(rng); domain_size];
        for power_of_tau in powers_of_tau.iter_mut().take(domain_size) {
            *power_of_tau = E::G1Affine::rand(rng);
        }
        PolyCk::<E> {
            powers_of_tau,
        }
    }

    /// Commits to a polynomial give the evals
    #[allow(unused)]
    pub fn commit(&self, pevals: &[E::ScalarField]) {
        let msm_time = start_timer!(|| "PolyCom MSM");
        let commitment = E::G1::msm(&self.powers_of_tau, pevals).unwrap();
        end_timer!(msm_time);
    }

    /// Creates an opening to a polynomial at a chosen point
    #[allow(unused)]
    pub fn open(
        &self,
        pevals: &Vec<E::ScalarField>,
        point: E::ScalarField,
        dom: &Radix2EvaluationDomain<E::ScalarField>,
    ) -> E::ScalarField {
        debug_assert_eq!(pevals.len(), dom.size(), "pevals length is not equal to m");
        let open_timer = start_timer!(|| "PolyCom Open");
        // Interpolate pevals to get coeffs
        let pcoeffs = dom.ifft(pevals);
        let p = DensePolynomial::from_coefficients_vec(pcoeffs);
        let point_eval = p.evaluate(&point); // Evaluate pcoeffs at point

        // Compute the quotient polynomial
        let p = DenseOrSparsePolynomial::from(p);
        let divisor = DenseOrSparsePolynomial::from(DensePolynomial::from_coefficients_vec(vec![
            -point,
            E::ScalarField::one(),
        ]));
        let qcoeffs = p.divide_with_q_and_r(&divisor).unwrap().1.coeffs().to_vec();

        // convert to evals
        let qevals = dom.fft(&qcoeffs);

        // Compute the proof pi
        let pi = E::G1::msm(&self.powers_of_tau, &qevals).unwrap();
        end_timer!(open_timer);

        point_eval
    }
}
