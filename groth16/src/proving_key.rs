#![allow(clippy::needless_range_loop)]

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_chunks, cfg_into_iter};
use dist_primitives::dmsm::packexp_from_public;
use secret_sharing::pss::PackedSharingParams;

use ark_ff::UniformRand;
use rand::Rng;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(
    Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct PackedProvingKeyShare<E: Pairing> {
    pub s: Vec<E::G1Affine>,
    pub u: Vec<E::G1Affine>,
    pub v: Vec<E::G2Affine>,
    pub w: Vec<E::G1Affine>,
    pub h: Vec<E::G1Affine>,
}

impl<E: Pairing> PackedProvingKeyShare<E>
where
    E::ScalarField: FftField,
    <<E as Pairing>::G1Affine as AffineRepr>::ScalarField: FftField,
    E::BaseField: PrimeField,
{
    /// Given a proving key, pack it into a vector of ProvingKeyShares.
    /// Each party will hold one share per PSS chunk.
    pub fn pack_from_arkworks_proving_key(
        pk: &ark_groth16::ProvingKey<E>,
        n_parties: usize,
        pp_g1: PackedSharingParams<
            <<E as Pairing>::G1Affine as AffineRepr>::ScalarField,
        >,
        pp_g2: PackedSharingParams<
            <<E as Pairing>::G2Affine as AffineRepr>::ScalarField,
        >,
    ) -> Vec<Self> {
        assert!(pp_g1.l == pp_g2.l);
        assert!(pp_g1.n == pp_g2.n);

        let pre_packed_s = cfg_into_iter!(pk.a_query.clone())
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_u = cfg_into_iter!(pk.h_query.clone())
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_w = cfg_into_iter!(pk.l_query.clone())
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_h = cfg_into_iter!(pk.b_g1_query.clone())
            .map(Into::into)
            .collect::<Vec<_>>();
        let pre_packed_v = cfg_into_iter!(pk.b_g2_query.clone())
            .map(Into::into)
            .collect::<Vec<_>>();

        let packed_s = cfg_chunks!(pre_packed_s, pp_g1.l)
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_u = cfg_chunks!(pre_packed_u, pp_g1.l)
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_w = cfg_chunks!(pre_packed_w, pp_g1.l)
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_h = cfg_chunks!(pre_packed_h, pp_g1.l)
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_v = cfg_chunks!(pre_packed_v, pp_g2.l)
            .map(|chunk| packexp_from_public::<E::G2>(chunk, &pp_g2))
            .collect::<Vec<_>>();

        cfg_into_iter!(0..n_parties)
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
        let pp_g1 = PackedSharingParams::new(4);
        let pp_g2 = PackedSharingParams::new(4);
        let n = 8;
        let shares =
            PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(
                &pk, n, pp_g1, pp_g2,
            );
        eprintln!("shares: {:?}", shares);
        // Do something with the shares
    }
}
