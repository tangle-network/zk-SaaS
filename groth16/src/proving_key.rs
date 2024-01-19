#![allow(clippy::needless_range_loop)]

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_chunks, cfg_into_iter};
use secret_sharing::pss::PackedSharingParams;

use ark_ff::UniformRand;
use rand::Rng;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(
    Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct PackedProvingKeyShare<E: Pairing> {
    /// s = `a_query[1..]`
    pub s: Vec<E::G1Affine>,
    /// u = `h_query`
    pub u: Vec<E::G1Affine>,
    /// w = `l_query`
    pub w: Vec<E::G1Affine>,
    /// h = `b_g1_query[1..]`
    pub h: Vec<E::G1Affine>,
    /// v = `b_g2_query[1..]`
    pub v: Vec<E::G2Affine>,
    pub a_query0: E::G1Affine,
    pub b_g1_query0: E::G1Affine,
    pub b_g2_query0: E::G2Affine,
    pub delta_g1: E::G1Affine,
    pub delta_g2: E::G2Affine,
    pub alpha_g1: E::G1Affine,
    pub beta_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
}

impl<E: Pairing> PackedProvingKeyShare<E>
where
    E::ScalarField: FftField + PrimeField,
    <<E as Pairing>::G1Affine as AffineRepr>::ScalarField: FftField,
    E::BaseField: PrimeField,
{
    /// Given a proving key, pack it into a vector of ProvingKeyShares.
    /// Each party will hold one share per PSS chunk.
    pub fn pack_from_arkworks_proving_key(
        pk: &ark_groth16::ProvingKey<E>,
        pp: PackedSharingParams<
            <<E as Pairing>::G1Affine as AffineRepr>::ScalarField,
        >,
    ) -> Vec<Self> {
        let pre_packed_s = cfg_into_iter!(pk.a_query.clone())
            .skip(1)
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_u = cfg_into_iter!(pk.h_query.clone())
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_w = cfg_into_iter!(pk.l_query.clone())
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_h = cfg_into_iter!(pk.b_g1_query.clone())
            .skip(1)
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_v = cfg_into_iter!(pk.b_g2_query.clone())
            .skip(1)
            .map(Into::into)
            .collect::<Vec<_>>();

        let packed_s = cfg_chunks!(pre_packed_s, pp.l)
            .map(|chunk| pp.det_pack::<E::G1>(chunk.to_vec()))
            .collect::<Vec<_>>();
        let packed_u = cfg_chunks!(pre_packed_u, pp.l)
            .map(|chunk| pp.det_pack::<E::G1>(chunk.to_vec()))
            .collect::<Vec<_>>();
        let packed_w = cfg_chunks!(pre_packed_w, pp.l)
            .map(|chunk| pp.det_pack::<E::G1>(chunk.to_vec()))
            .collect::<Vec<_>>();
        let packed_h = cfg_chunks!(pre_packed_h, pp.l)
            .map(|chunk| pp.det_pack::<E::G1>(chunk.to_vec()))
            .collect::<Vec<_>>();
        let packed_v = cfg_chunks!(pre_packed_v, pp.l)
            .map(|chunk| pp.det_pack::<E::G2>(chunk.to_vec()))
            .collect::<Vec<_>>();

        cfg_into_iter!(0..pp.n)
            .map(|i| {
                let s_shares = cfg_into_iter!(0..packed_s.len())
                    .map(|j| packed_s[j][i].into())
                    .collect::<Vec<_>>();
                let u_shares = cfg_into_iter!(0..packed_u.len())
                    .map(|j| packed_u[j][i].into())
                    .collect::<Vec<_>>();
                let v_shares = cfg_into_iter!(0..packed_v.len())
                    .map(|j| packed_v[j][i].into())
                    .collect::<Vec<_>>();
                let w_shares = cfg_into_iter!(0..packed_w.len())
                    .map(|j| packed_w[j][i].into())
                    .collect::<Vec<_>>();
                let h_shares = cfg_into_iter!(0..packed_h.len())
                    .map(|j| packed_h[j][i].into())
                    .collect::<Vec<_>>();

                PackedProvingKeyShare::<E> {
                    s: s_shares,
                    u: u_shares,
                    v: v_shares,
                    w: w_shares,
                    h: h_shares,
                    a_query0: pk.a_query[0],
                    b_g1_query0: pk.b_g1_query[0],
                    b_g2_query0: pk.b_g2_query[0],
                    delta_g1: pk.delta_g1,
                    delta_g2: pk.vk.delta_g2,
                    alpha_g1: pk.vk.alpha_g1,
                    beta_g1: pk.beta_g1,
                    beta_g2: pk.vk.beta_g2,
                }
            })
            .collect()
    }

    pub fn rand<R: Rng>(
        rng: &mut R,
        domain_size: usize,
        pp: &PackedSharingParams<E::ScalarField>,
    ) -> Self {
        // println!("a_query:{}", pk.a_query.len());
        let mut s_shares: Vec<E::G1Affine> =
            vec![E::G1Affine::rand(rng); domain_size / pp.l];
        for i in 1..s_shares.len() {
            s_shares[i] = E::G1Affine::rand(rng);
        }

        // println!("h_query:{}", pk.h_query.len());
        let mut u_shares = vec![E::G1Affine::rand(rng); domain_size * 2 / pp.l];
        for i in 1..u_shares.len() {
            u_shares[i] = E::G1Affine::rand(rng);
        }

        // println!("l_query:{}", pk.l_query.len());
        let mut w_shares = vec![E::G1Affine::rand(rng); domain_size / pp.l];
        for i in 1..w_shares.len() {
            w_shares[i] = E::G1Affine::rand(rng);
        }

        // println!("b_g1_query:{}", pk.b_g1_query.len());
        let mut h_shares = vec![E::G1Affine::rand(rng); domain_size / pp.l];
        for i in 1..h_shares.len() {
            h_shares[i] = E::G1Affine::rand(rng);
        }

        // println!("b_g2_query:{}", pk.b_g2_query.len());
        let mut v_shares = vec![E::G2Affine::rand(rng); domain_size / pp.l];
        for i in 1..v_shares.len() {
            v_shares[i] = E::G2Affine::rand(rng);
        }

        PackedProvingKeyShare::<E> {
            s: s_shares,
            u: u_shares,
            v: v_shares,
            w: w_shares,
            h: h_shares,
            a_query0: E::G1Affine::rand(rng),
            b_g1_query0: E::G1Affine::rand(rng),
            b_g2_query0: E::G2Affine::rand(rng),
            delta_g1: E::G1Affine::rand(rng),
            delta_g2: E::G2Affine::rand(rng),
            alpha_g1: E::G1Affine::rand(rng),
            beta_g1: E::G1Affine::rand(rng),
            beta_g2: E::G2Affine::rand(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_bn254::Bn254;
    use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::Groth16;

    const L: usize = 2;

    #[test]
    fn packed_pk_from_arkworks_pk() {
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_module_path(false)
            .is_test(true)
            .try_init();
        let cfg = CircomConfig::<Bn254>::new(
            "../fixtures/sha256/sha256_js/sha256.wasm",
            "../fixtures/sha256/sha256.r1cs",
        )
        .unwrap();
        let builder = CircomBuilder::new(cfg);
        let circom = builder.setup();
        let rng = &mut ark_std::rand::thread_rng();
        let (pk, _vk) =
            Groth16::<Bn254, CircomReduction>::circuit_specific_setup(
                circom, rng,
            )
            .unwrap();
        let pp = PackedSharingParams::new(L);
        let _shares =
            PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(
                &pk, pp,
            );
    }
}
