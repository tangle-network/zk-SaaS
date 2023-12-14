use ark_poly::{domain::{EvaluationDomain, DomainCoeff}, Radix2EvaluationDomain};

use ark_ff::FftField;
use ark_std::{UniformRand, rand::Rng};

/// Packed Secret Sharing Parameters
///
/// Configures the parameters for packed secret sharing. It assumes that the number of parties is `4l`,
/// the corrupting threshold is `l-1`, and checks that the number of parties (n) equals to `2(t + l + 1)`.
///
/// ## Note
/// Currently the packed secret sharing is deterministic, but it can easily be extended to add random values when packing
#[derive(Copy, Clone, Debug, PartialEq)]
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
    pub fn det_pack<T: DomainCoeff<F> + UniformRand>(&self, secrets: Vec<T>) -> Vec<T> {
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
    pub fn pack<T: DomainCoeff<F> + UniformRand>(&self, secrets: Vec<T>, rng: &mut impl Rng) -> Vec<T> {
        debug_assert!(secrets.len() == self.l, "Secrets length mismatch");
        
        let mut result = secrets;

        // Resize the secrets with t+1 random points
        let rand_points = (0..self.t + 1)
            .map(|_| T::rand(rng))
            .collect::<Vec<T>>();
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
        let secrets = pp.unpack(shares);

        assert_eq!(expected, secrets);
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
        let mul_secrets = pp.unpack2(mul_shares);

        assert_eq!(expected, mul_secrets);
    }
}
