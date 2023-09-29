use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use secret_sharing::pss::PackedSharingParams;

use ark_ff::UniformRand;
use ark_std::{end_timer, start_timer};
use rand::Rng;

#[derive(
    Clone, Debug, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct PackProvingKeyShare<E: Pairing> {
    pub s: Vec<E::G1Affine>,
    pub u: Vec<E::G1Affine>,
    pub v: Vec<E::G2Affine>,
    pub w: Vec<E::G1Affine>,
    pub h: Vec<E::G1Affine>,
}

impl<E: Pairing> PackProvingKeyShare<E>
where
    E::ScalarField: FftField + PrimeField,
{
    pub fn pack_from_arkworks_proving_key(
        pk: &ark_groth16::ProvingKey<E>,
        n_parties: usize,
        pp: PackedSharingParams<E::ScalarField>,
    ) -> Vec<Self> {
        let mut packed_proving_key_shares = Vec::new();
        let pp = PackedSharingParams::<E::ScalarField>::new(n_parties);

        let pre_packed_s = pk.a_query
            .iter()
            .map(|p: &E::G1Affine| p
                .xy()
                .map(|p| [*p.0, *p.1])
                .unwrap()
            )
            .flatten()
            .collect::<Vec<<<E as Pairing>::G1Affine as AffineRepr>::BaseField>>();
        let pre_packed_u = pk.h_query;
        let pre_packed_w = pk.l_query;
        let pre_packed_h = pk.b_g1_query;
        let pre_packed_v = pk.b_g2_query;

        // let packed_s = pre_packed_s.chunks(pp.l).map(|chunk| pp.pack_from_public(chunk.to_vec())).collect::<Vec<_>>();
        // let packed_u = pre_packed_u.chunks(pp.l).map(|chunk| pp.pack_from_public(chunk.to_vec())).collect::<Vec<_>>();
        // let packed_w = pre_packed_w.chunks(pp.l).map(|chunk| pp.pack_from_public(chunk.to_vec())).collect::<Vec<_>>();
        // let packed_h = pre_packed_h.chunks(pp.l).map(|chunk| pp.pack_from_public(chunk.to_vec())).collect::<Vec<_>>();
        // let packed_v = pre_packed_v.chunks(pp.l).map(|chunk| pp.pack_from_public(chunk.to_vec())).collect::<Vec<_>>();

        for i in 0..n_parties {
            let mut s_shares = Vec::new();
            let mut u_shares = Vec::new();
            let mut v_shares = Vec::new();
            let mut w_shares = Vec::new();
            let mut h_shares = Vec::new();

            packed_proving_key_shares.push(PackProvingKeyShare::<E> {
                s: s_shares,
                u: u_shares,
                v: v_shares,
                w: w_shares,
                h: h_shares,
            });
        }
        packed_proving_key_shares
    }

    pub fn rand<R: Rng>(
        rng: &mut R,
        domain_size: usize,
        pp: &PackedSharingParams<E::ScalarField>,
    ) -> Self {
        let outer_time = start_timer!(|| "Dummy CRS packing");
        let inner_time = start_timer!(|| "Packing S");
        // println!("a_query:{}", pk.a_query.len());
        let mut s_shares: Vec<E::G1Affine> =
            vec![E::G1Affine::rand(rng); domain_size / pp.l];
        for i in 1..s_shares.len() {
            s_shares[i] = E::G1Affine::rand(rng);
        }
        end_timer!(inner_time);

        let inner_time = start_timer!(|| "Packing U");
        // println!("h_query:{}", pk.h_query.len());
        let mut u_shares = vec![E::G1Affine::rand(rng); domain_size * 2 / pp.l];
        for i in 1..u_shares.len() {
            u_shares[i] = E::G1Affine::rand(rng);
        }
        end_timer!(inner_time);

        let inner_time = start_timer!(|| "Packing W");
        // println!("l_query:{}", pk.l_query.len());
        let mut w_shares = vec![E::G1Affine::rand(rng); domain_size / pp.l];
        for i in 1..w_shares.len() {
            w_shares[i] = E::G1Affine::rand(rng);
        }
        end_timer!(inner_time);

        let inner_time = start_timer!(|| "Packing H");
        // println!("b_g1_query:{}", pk.b_g1_query.len());
        let mut h_shares = vec![E::G1Affine::rand(rng); domain_size / pp.l];
        for i in 1..h_shares.len() {
            h_shares[i] = E::G1Affine::rand(rng);
        }
        end_timer!(inner_time);

        let inner_time = start_timer!(|| "Packing V");
        // println!("b_g2_query:{}", pk.b_g2_query.len());
        let mut v_shares = vec![E::G2Affine::rand(rng); domain_size / pp.l];
        for i in 1..v_shares.len() {
            v_shares[i] = E::G2Affine::rand(rng);
        }
        end_timer!(inner_time);
        end_timer!(outer_time);

        PackProvingKeyShare::<E> {
            s: s_shares,
            u: u_shares,
            v: v_shares,
            w: w_shares,
            h: h_shares,
        }
    }
}
