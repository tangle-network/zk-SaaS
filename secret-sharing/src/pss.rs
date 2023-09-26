use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};

use ark_ff::FftField;

/// Currently the packed secret sharing is deterministic, but it can easily be extended to add random values when packing
#[derive(Debug, Clone, PartialEq)]
pub struct PackedSharingParams<F>
where
    F: FftField,
{
    pub t: usize,                           // Corruption threshold
    pub l: usize,                           // Packing factor
    pub n: usize,                           // Number of parties
    pub share: Radix2EvaluationDomain<F>,   // Share domain
    pub secret: Radix2EvaluationDomain<F>,  // Secrets domain
    pub secret2: Radix2EvaluationDomain<F>, // Secrets2 domain
}

impl<F: FftField> PackedSharingParams<F> {
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

    /// Packs secrets into shares
    #[allow(unused)]
    pub fn pack_from_public(&self, mut secrets: Vec<F>) -> Vec<F> {
        self.pack_from_public_in_place(&mut secrets);
        secrets
    }

    /// Packs secrets into shares in place
    #[allow(unused)]
    pub fn pack_from_public_in_place(&self, secrets: &mut Vec<F>) {
        // interpolating on secrets domain
        self.secret.ifft_in_place(secrets);

        // evaluate on share domain
        self.share.fft_in_place(secrets);
    }

    /// Unpacks shares of degree t+l into secrets
    #[allow(unused)]
    pub fn unpack(&self, mut shares: Vec<F>) -> Vec<F> {
        self.unpack_in_place(&mut shares);
        shares
    }

    /// Unpacks shares of degree 2(t+l) into secrets
    #[allow(unused)]
    pub fn unpack2(&self, mut shares: Vec<F>) -> Vec<F> {
        self.unpack2_in_place(&mut shares);
        shares
    }

    /// Unpacks shares of degree t+l into secrets in place
    #[allow(unused)]
    pub fn unpack_in_place(&self, shares: &mut Vec<F>) {
        // interpolating on share domain
        self.share.ifft_in_place(shares);

        // assert that all but first t+l+1 elements are zero
        // #[cfg(debug_assertions)]
        // {
        //     for i in self.l + self.t + 1..shares.len() {
        //         debug_assert!(shares[i].is_zero(), "Unpack failed");
        //     }
        // }

        // evaluate on secrets domain
        self.secret.fft_in_place(shares);

        // truncate to remove the randomness
        shares.truncate(self.l);
    }

    /// Unpacks shares of degree 2(t+l) into secrets in place
    #[allow(unused)]
    pub fn unpack2_in_place(&self, shares: &mut Vec<F>) {
        // interpolating on share domain
        self.share.ifft_in_place(shares);

        // assert that all but first 2(t+l)+1 elements are zero
        #[cfg(debug_assertions)]
        {
            for item in shares.iter().skip(2 * (self.l + self.t) + 1) {
                debug_assert!(item.is_zero(), "Unpack2 failed");
            }
        }

        // evaluate on secrets domain
        self.secret2.fft_in_place(shares);

        // drop alternate elements from shares array and only iterate till 2l as the rest of it is randomness
        *shares = shares[0..2 * self.l].iter().step_by(2).copied().collect();
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
    fn test_pack_from_public() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let mut secrets = secrets.to_vec();

        let expected = secrets.clone();

        pp.pack_from_public_in_place(&mut secrets);
        pp.unpack_in_place(&mut secrets);

        assert_eq!(expected, secrets);
    }

    #[test]
    fn test_multiplication() {
        let pp = PackedSharingParams::<F>::new(L);

        let rng = &mut ark_std::test_rng();
        let secrets: [F; L] = UniformRand::rand(rng);
        let mut secrets = secrets.to_vec();
        let expected: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        pp.pack_from_public_in_place(&mut secrets);

        let mut shares: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        pp.unpack2_in_place(&mut shares);

        assert_eq!(expected, shares);
    }
}
