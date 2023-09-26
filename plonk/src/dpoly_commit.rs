use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
use dist_primitives::dfft::{d_fft, d_ifft};
use dist_primitives::dmsm::d_msm;
use dist_primitives::utils::deg_red::deg_red;
use rand::Rng;
use secret_sharing::pss::PackedSharingParams;

#[derive(Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PackPolyCk<E: Pairing> {
    pub powers_of_tau: Vec<E::G1Affine>, //We assume that we have eval version
}

impl<E: Pairing> PackPolyCk<E> {
    #[allow(unused)]
    pub fn new<R: Rng>(
        domain_size: usize,
        rng: &mut R,
        pp: &PackedSharingParams<E::ScalarField>,
    ) -> Self {
        // using dummy to speedup testing
        let mut powers_of_tau: Vec<E::G1Affine> = vec![E::G1Affine::rand(rng); domain_size / pp.l];
        for power_of_tau in powers_of_tau.iter_mut().take(domain_size / pp.l) {
            *power_of_tau = E::G1Affine::rand(rng);
        }
        PackPolyCk::<E> {
            powers_of_tau,
        }
    }

    /// Interactively commits to a polynomial give packed shares of the evals
    #[allow(unused)]
    pub fn commit(
        &self,
        peval_share: &Vec<E::ScalarField>,
        pp: &PackedSharingParams<E::ScalarField>,
    ) {
        let commitment = d_msm::<E::G1>(&self.powers_of_tau, peval_share.as_slice(), pp);
        // actually getting back shares but king can publish the commitment
    }

    /// Interactively creates an opening to a polynomial at a chosen point
    #[allow(unused)]
    pub fn open(
        &self,
        peval_share: &Vec<E::ScalarField>,
        point: E::ScalarField,
        dom: &Radix2EvaluationDomain<E::ScalarField>,
        pp: &PackedSharingParams<E::ScalarField>,
    ) -> E::ScalarField {
        debug_assert_eq!(
            peval_share.len() * pp.l,
            dom.size(),
            "pevals length is not equal to m/l"
        );
        // Interpolate pevals to get coeffs
        let pcoeff_share = d_ifft(peval_share.clone(), false, 1, false, dom, pp);

        // distributed poly evaluation
        let powers_of_r_share = E::ScalarField::from(123_u32); // packed shares of r drop from sky
        let point_eval_share = pcoeff_share
            .iter()
            .map(|&a| a * powers_of_r_share)
            .sum::<E::ScalarField>();

        // do degree reduction and King publishes answer
        let point_eval_share = deg_red(vec![point_eval_share], pp)[0];

        // Compute the quotient polynomial
        // During iFFT king sends over the "truncated pcoeff_shares". Do FFT on this

        let ptrunc_evals = d_fft(pcoeff_share, false, 1, false, dom, pp);
        let toep_mat_share = E::ScalarField::from(123_u32); // packed shares of toeplitz matrix drop from sky
        let timer_div = start_timer!(|| "Division");
        let q_evals = ptrunc_evals
            .into_iter()
            .map(|a| a * toep_mat_share)
            .collect::<Vec<E::ScalarField>>();
        end_timer!(timer_div);

        // don't have to do degree reduction since it's a secret value multiplied by two public values
        // we could pack two public values together but that would mean two msms instead of one

        // Compute the proof pi
        let pi: E::G1 = d_msm(&self.powers_of_tau, &q_evals, pp);

        point_eval_share
    }
}
