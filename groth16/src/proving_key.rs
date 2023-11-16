#![allow(clippy::needless_range_loop)]

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_chunks, cfg_into_iter, cfg_iter};
use dist_primitives::dmsm::{
    packexp_from_public, packexp_from_public_in_place,
};
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
    E::ScalarField: FftField + PrimeField,
    <<E as Pairing>::G1Affine as AffineRepr>::ScalarField: FftField,
    E::BaseField: PrimeField,
{
    /// Given a proving key, pack it into a vector of ProvingKeyShares.
    /// Each party will hold one share per PSS chunk.
    pub fn pack_from_arkworks_proving_key(
        pk: &ark_groth16::ProvingKey<E>,
        pp_g1: PackedSharingParams<
            <<E as Pairing>::G1Affine as AffineRepr>::ScalarField,
        >,
        pp_g2: PackedSharingParams<
            <<E as Pairing>::G2Affine as AffineRepr>::ScalarField,
        >,
    ) -> Vec<Self> {
        assert!(pp_g1.l == pp_g2.l);
        assert!(pp_g1.n == pp_g2.n);
        let n = pp_g1.n;

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

        cfg_into_iter!(0..n)
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

    /// Given a proving key, pack it into a ProvingKeyShare.
    /// For only the given party index.
    pub fn pack_from_arkworks_proving_key_and_party_index(
        party_index: usize,
        pk: &ark_groth16::ProvingKey<E>,
        pp_g1: PackedSharingParams<
            <<E as Pairing>::G1Affine as AffineRepr>::ScalarField,
        >,
        pp_g2: PackedSharingParams<
            <<E as Pairing>::G2Affine as AffineRepr>::ScalarField,
        >,
    ) -> Self {
        assert!(pp_g1.l == pp_g2.l);
        assert!(pp_g1.n == pp_g2.n);
        let n = pp_g1.n;

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

        let num_of_chunks_per_party = |x| x / n;
        let start = |x| party_index * num_of_chunks_per_party(x);

        let packed_s = cfg_chunks!(pre_packed_s, pp_g1.l)
            .skip(start(pre_packed_s.len()))
            .take(num_of_chunks_per_party(pre_packed_s.len()))
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_u = cfg_chunks!(pre_packed_u, pp_g1.l)
            .skip(start(pre_packed_u.len()))
            .take(num_of_chunks_per_party(pre_packed_u.len()))
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_w = cfg_chunks!(pre_packed_w, pp_g1.l)
            .skip(start(pre_packed_w.len()))
            .take(num_of_chunks_per_party(pre_packed_w.len()))
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_h = cfg_chunks!(pre_packed_h, pp_g1.l)
            .skip(start(pre_packed_h.len()))
            .take(num_of_chunks_per_party(pre_packed_h.len()))
            .map(|chunk| packexp_from_public::<E::G1>(chunk, &pp_g1))
            .collect::<Vec<_>>();
        let packed_v = cfg_chunks!(pre_packed_v, pp_g2.l)
            .skip(start(pre_packed_v.len()))
            .take(num_of_chunks_per_party(pre_packed_v.len()))
            .map(|chunk| packexp_from_public::<E::G2>(chunk, &pp_g2))
            .collect::<Vec<_>>();

        let i = party_index;
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
    use ark_std::cfg_chunks_mut;

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
        let pp_g1 = PackedSharingParams::new(L);
        let pp_g2 = PackedSharingParams::new(L);
        let _shares =
            PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(
                &pk, pp_g1, pp_g2,
            );
    }

    #[test]
    fn chunking() {
        // imagine we have a vector of length 32
        let v = vec![0u32; 32];
        // and we have 4 parties
        // we want to split the vector into 4 chunks
        // each party will hold one chunk
        // the first party will hold the first 8 elements
        // the second party will hold the second 8 elements
        // and so on
        let n = 4;
        let chunk_size = v.len() / n;
        let chunks = v.chunks(chunk_size).collect::<Vec<_>>();
        assert_eq!(chunks.len(), n);
        for i in 0..n {
            assert_eq!(chunks[i].len(), chunk_size);
        }
        let my_index = 2;
        let my_chunk1 = chunks[my_index];

        // Now, Imagine we have a vector v of length 32
        // and we have 4 parties
        // we want to get the chunk of the party with index 2
        // without splitting the vector into chunks first.
        // We want to do this with iterators
        let n = 4;
        let chunk_size = v.len() / n;
        let my_chunk2 = v
            .iter()
            .skip(my_index * chunk_size)
            .take(chunk_size)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(my_chunk2.len(), chunk_size);
        assert_eq!(my_chunk2, my_chunk1);
    }

    #[test]
    fn dbg_w() {
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
        let pp_g1 = PackedSharingParams::new(L);
        let n = pp_g1.n;
        let idx = 2;

        let left = {
            let mut pre_packed_w = cfg_into_iter!(pk.l_query.clone())
                .map(Into::into)
                .collect::<Vec<_>>();
            let packed_w = cfg_chunks_mut!(pre_packed_w, pp_g1.l)
                .map(|chunk| {
                    packexp_from_public::<<Bn254 as Pairing>::G1>(chunk, &pp_g1)
                })
                .collect::<Vec<_>>();
            cfg_into_iter!(packed_w).map(|x| x[idx]).collect::<Vec<_>>()
        };

        let right = {
            let pre_packed_w = cfg_into_iter!(pk.l_query.clone())
                .map(Into::into)
                .collect::<Vec<_>>();
            let packed_w = cfg_chunks!(pre_packed_w, pp_g1.l)
                .map(|chunk| {
                    packexp_from_public::<<Bn254 as Pairing>::G1>(chunk, &pp_g1)
                })
                .collect::<Vec<_>>();
            cfg_into_iter!(0..n)
                .map(|i| cfg_iter!(packed_w).map(|x| x[i]).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        };

        assert_eq!(left.len(), right[idx].len());
        assert_eq!(left, right[idx]);
    }
}
