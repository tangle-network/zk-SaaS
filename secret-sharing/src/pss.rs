use ark_poly::{domain::DomainCoeff, EvaluationDomain, Radix2EvaluationDomain};

use ark_ff::{batch_inversion, FftField};
use ark_std::{rand::Rng, UniformRand};

use crate::utils::{eval, get_zero_roots, syn_div};

/// Packed Secret Sharing Parameters
///
/// Configures the parameters for packed secret sharing. It assumes that the number of parties is `4l`,
/// the corrupting threshold is `l-1`, and checks that the number of parties (n) equals to `2(t + l + 1)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PackedSharingParams<F>
where
    F: FftField,
{
    /// Corrupting threshold
    pub t: usize,
    /// Packing factor
    pub l: usize,
    /// Number of parties
    pub n: usize,
    /// Share domain
    pub share: Radix2EvaluationDomain<F>,
    /// Secrets domain
    pub secret: Radix2EvaluationDomain<F>,
    /// Secrets2 domain
    pub secret2: Radix2EvaluationDomain<F>,
}

impl<F: FftField> PackedSharingParams<F> {
    /// Creates a new instance of PackedSharingParams with the given packing factor
    #[allow(unused)]
    pub fn new(l: usize) -> Self {
        let n = l * 4;
        let t = l - 1;
        debug_assert_eq!(n, 2 * (t + l + 1));

        let share = Radix2EvaluationDomain::<F>::new(n).unwrap();
        let secret = Radix2EvaluationDomain::<F>::new(l + t + 1)
            .unwrap()
            .get_coset(F::GENERATOR)
            .unwrap();
        let secret2 = Radix2EvaluationDomain::<F>::new(2 * (l + t + 1))
            .unwrap()
            .get_coset(F::GENERATOR)
            .unwrap();

        debug_assert_eq!(share.size(), n);
        debug_assert_eq!(secret.size(), l + t + 1);
        debug_assert_eq!(secret2.size(), 2 * (l + t + 1));

        PackedSharingParams {
            t,
            l,
            n,
            share,
            secret,
            secret2,
        }
    }

    /// Deterministically packs secrets into shares
    #[allow(unused)]
    pub fn det_pack<T: DomainCoeff<F> + UniformRand>(
        &self,
        secrets: Vec<T>,
    ) -> Vec<T> {
        debug_assert!(secrets.len() == self.l, "Secrets length mismatch");

        let mut result = secrets;

        // Resize the secrets with t+1 zeros
        result.append(&mut vec![T::zero(); self.t + 1]);

        // interpolating on secrets domain
        self.secret.ifft_in_place(&mut result);

        // evaluate on share domain
        self.share.fft_in_place(&mut result);

        result
    }

    /// Packs secrets into shares
    #[allow(unused)]
    pub fn pack<T: DomainCoeff<F> + UniformRand>(
        &self,
        secrets: Vec<T>,
        rng: &mut impl Rng,
    ) -> Vec<T> {
        debug_assert!(secrets.len() == self.l, "Secrets length mismatch");

        let mut result = secrets;

        // Resize the secrets with t+1 random points
        let rand_points =
            (0..self.t + 1).map(|_| T::rand(rng)).collect::<Vec<T>>();
        result.extend_from_slice(&rand_points);

        // interpolating on secrets domain
        self.secret.ifft_in_place(&mut result);

        // evaluate on share domain
        self.share.fft_in_place(&mut result);

        result
    }

    /// Unpacks shares of degree t+l into secrets
    #[allow(unused)]
    pub fn unpack<T: DomainCoeff<F>>(&self, shares: Vec<T>) -> Vec<T> {
        let mut result = shares;

        // interpolating on share domain
        self.share.ifft_in_place(&mut result);

        // evaluate on secrets domain
        self.secret.fft_in_place(&mut result);

        // truncate to remove the randomness
        result.truncate(self.l);

        result
    }

    /// Unpacks shares of degree 2(t+l) into secrets
    #[allow(unused)]
    pub fn unpack2<T: DomainCoeff<F>>(&self, shares: Vec<T>) -> Vec<T> {
        let mut result = shares;

        // interpolating on share domain
        self.share.ifft_in_place(&mut result);

        // assert that all but first 2(t+l)+1 elements are zero
        #[cfg(debug_assertions)]
        {
            for item in result.iter().skip(2 * (self.l + self.t) + 1) {
                debug_assert!(item.is_zero(), "Unpack2 failed");
            }
        }

        // evaluate on secrets domain
        self.secret2.fft_in_place(&mut result);

        // drop alternate elements from shares array and only iterate till 2l as the rest of it is randomness
        result = result[0..2 * self.l].iter().step_by(2).copied().collect();

        result
    }

    /// Runs lagrange interpolation to unpack the secrets. Can be used when some shares are missing.
    /// todo: can be optimized by compting secrets directly instead of first interpolating the polynomial
    pub fn lagrange_unpack<T: DomainCoeff<F>>(
        &self,
        shares: Vec<T>,
        parties: Vec<u32>,
    ) -> Vec<T> {
        // first generate lagrange coefficients for the parties specified
        // these are the lagrange polynomials corresponding to the share domain, evaluated at the secret domain
        // code ported from https://github.com/facebook/winterfell/blob/a450b818f7ec70e7d40628c789845a93d6e0c030/math/src/polynom/mod.rs#L626
        // Note: ordering of polynomial coefficients is largest power -> smaller power

        debug_assert!(
            shares.len() == parties.len(),
            "Shares and parties length mismatch"
        );

        let mut xs = Vec::new();
        let share_elements = self.share.elements().collect::<Vec<F>>();
        for i in 0..parties.len() {
            xs.push(share_elements[parties[i] as usize]);
        }

        let roots = get_zero_roots(&xs);
        let numerators: Vec<Vec<F>> =
            xs.iter().map(|&x| syn_div(&roots, 1, x)).collect();
        println!("numerators: {}", numerators.len());
        let mut denominators: Vec<F> =
            numerators.iter().zip(xs).map(|(f, x)| eval(f, x)).collect();
        batch_inversion(&mut denominators);

        // result will contain coefficent form of the polynomial
        let mut result = vec![T::zero(); numerators.len()];
        for i in 0..shares.len() {
            let mut y_slice = shares[i];
            y_slice *= denominators[i];
            for (j, res) in result.iter_mut().enumerate() {
                let mut tmp = y_slice;
                tmp *= numerators[i][j];
                *res += tmp;
            }
        }

        // evaluate on secrets domain
        self.secret2.fft_in_place(&mut result);

        // drop alternate elements from shares array and only iterate till 2l as the rest of it is randomness
        result = result[0..2 * self.l].iter().step_by(2).copied().collect();

        result
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr as F;
    use ark_std::UniformRand;
    use PackedSharingParams;

    const L: usize = 4;
    const N: usize = L * 4;
    const T: usize = N / 2 - L - 1;

    #[test]
    fn test_initialize() {
        let pp = PackedSharingParams::<F>::new(L);
        assert_eq!(pp.t, L - 1);
        assert_eq!(pp.l, L);
        assert_eq!(pp.n, N);
        assert_eq!(pp.share.size(), N);
        assert_eq!(pp.secret.size(), L + T + 1);
        assert_eq!(pp.secret2.size(), 2 * (L + T + 1));
    }

    #[test]
    fn test_packing() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();

        let expected = secrets.clone();

        let shares = pp.pack(secrets, rng);
        let secrets = pp.unpack(shares.clone());

        // using only a subset of shares here
        let lagrange_secrets = pp.lagrange_unpack(
            shares[0..pp.n - pp.t].to_vec(),
            (0..(pp.n - pp.t) as u32).collect(),
        );

        assert_eq!(expected, secrets);
        assert_eq!(expected, lagrange_secrets);
    }

    #[test]
    fn test_det_packing() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();

        let expected = secrets.clone();

        let shares = pp.det_pack(secrets);
        let secrets = pp.unpack(shares);

        assert_eq!(expected, secrets);
    }

    #[test]
    fn test_multiplication() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();
        let expected: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        let shares = pp.pack(secrets, rng);
        let mul_shares: Vec<F> = shares.iter().map(|x| (*x) * (*x)).collect();
        let mul_secrets = pp.unpack2(mul_shares.clone());

        // using only a subset of shares here
        let lagrange_secrets = pp.lagrange_unpack(
            mul_shares[0..pp.n].to_vec(),
            (0..(pp.n) as u32).collect(),
        );

        assert_eq!(expected, mul_secrets);
        assert_eq!(expected, lagrange_secrets);
    }
}
