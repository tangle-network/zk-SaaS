use ark_ff::{FftField, Zero};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, univariate::{DensePolynomial, DenseOrSparsePolynomial}};
use crate::pss::PackedSharingParams;

impl<F: FftField> PackedSharingParams<F> {
    // todo: speed up gcd using FFT
    // below will serve as reference implementation
    pub fn partial_xgcd(
        &self,
        a: DensePolynomial<F>,
        b: DensePolynomial<F>,
        codelength: usize,
        dimension: usize,
    ) -> (DensePolynomial<F>, DensePolynomial<F>) {
        // Translated into rust from SageMath's implementation
        // https://github.com/sagemath/sage/blob/b002b63fb42e44f5404a1f8856378aa1ba5b2b1c/src/sage/coding/grs_code.py#L1541
        // Performs an Euclidean algorithm on ``a`` and ``b`` until a remainder
        // has degree less than `(n+k)/2`, `n` being the length of the
        // code, `k` its dimension, and returns `(r, s)` such that in the step
        // just before termination, `r = a s + b t`.
        let stop = (dimension + codelength) / 2;
        let mut s = DensePolynomial::<F>::from_coefficients_slice(&[F::one()]);
        let mut prev_s = DensePolynomial::<F>::from_coefficients_slice(&[F::zero()]);

        let mut r = b;
        let mut prev_r = a;

        while r.degree() >= stop {
            let q = &prev_r / &r;

            let tmp = r.clone();
            r = &prev_r - &(&q * &r);
            prev_r = tmp.clone();

            let tmp = s.clone();
            s = &prev_s - &(&q * &s);
            prev_s = tmp.clone();
        }

        return (r, s);
    }

    pub fn decode_to_message(
        &self,
        received_code: Vec<F>,
        codelength: usize,
        dimension: usize,
    ) -> DensePolynomial<F> {
        // Based on SageMath's implementation
        // https://github.com/sagemath/sage/blob/b002b63fb42e44f5404a1f8856378aa1ba5b2b1c/src/sage/coding/grs_code.py#L1584
        // Decodes a received code word ``received_code`` into a code word and the corresponding message.

        // todo: add an early return if the received code is already a codeword
        // do ifft -- should have "low enough (dimension-1)" degree.

        // interpolate the received code
        let r = DensePolynomial::from_coefficients_slice(&self.share.ifft(&received_code));
        
        // compute gcd between vanishing polynomial and received code
        let z = self.share.vanishing_polynomial();

        let (q1, q0) = self.partial_xgcd(z.clone().into(), r.clone(), codelength, dimension);
        let q1 = DenseOrSparsePolynomial::from(q1);
        let q0 = DenseOrSparsePolynomial::from(q0);
        
        // h should be the message
        let (h, rem) = q1.divide_with_q_and_r(&q0).unwrap();
        
        // todo: add various checks for failed decoding
        assert!(rem.is_zero());

        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{fields::MontConfig, Fp, MontBackend};
    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = Fp<MontBackend<FqConfig, 1>, 1>;

    #[test]
    fn test_partial_xgcd() {
        let pp = super::PackedSharingParams::<F17>::new(2);
        let a = DensePolynomial::<F17>::from_coefficients_slice(&[
            F17::from(8),
            F17::from(9),
            F17::from(5),
        ]);
        let b = DensePolynomial::<F17>::from_coefficients_slice(&[
            F17::from(5),
            F17::from(3),
            F17::from(10),
        ]);
        let (r, s) = pp.partial_xgcd(a, b, 16, 10);
        assert_eq!(
            r,
            DensePolynomial::<F17>::from_coefficients_slice(&[
                F17::from(5),
                F17::from(3),
                F17::from(10)
            ])
        );
        assert_eq!(
            s,
            DensePolynomial::<F17>::from_coefficients_slice(&[F17::from(1)])
        );
    }

    #[test]
    fn test_error_correction() {
        let msg = [1, 4];
        let m = msg.iter().map(|x| F17::from(*x)).collect::<Vec<_>>();

        let pp = super::PackedSharingParams::<F17>::new(2);
        
        let mut code = pp.share.fft(&m);
        code[1] += F17::from(1); //error

        let decoded = pp.decode_to_message(code.clone(), 8, 4);
        assert_eq!(decoded, DensePolynomial::<F17>::from_coefficients_slice(&m));
    }
}
