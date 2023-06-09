// Evalauting a distributed version of partial products
// Given x1, x2, .., xn, output x1, x1*x2, x1*x2*x3, .., x1*x2*..*xn

use crate::{
    channel::channel::MpcSerNet,
    utils::{
        deg_red::deg_red,
        pack::{pack_vec, transpose},
    },
};
use ark_ff::{FftField, Field, PrimeField};
use ark_std::{end_timer, start_timer};
use mpc_net::MpcMultiNet as Net;
use secret_sharing::pss::PackedSharingParams;

// Given pre-processed randomness [s], [s^-1]
pub fn d_pp<F: FftField + PrimeField + Field>(
    num: Vec<F>,
    den: Vec<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<F> {
    // using some dummy randomness
    let s = F::from(1 as u32);
    let sinv = s.inverse().unwrap();

    // multiply all entries of px by of s
    let dpp_rand_timer = start_timer!(|| "DppRand");
    let num_rand = num.iter().map(|&x| x * s).collect::<Vec<_>>();
    let mut den_rand = den.iter().map(|&x| x * s).collect::<Vec<_>>();
    end_timer!(dpp_rand_timer);

    let mut numden_rand = num_rand;
    numden_rand.append(&mut den_rand);

    // Along with degree reduction
    // King recovers secrets, computes partial products and repacks
    let communication_timer = start_timer!(|| "ComToKing");
    let received_shares = Net::send_to_king(&numden_rand);
    end_timer!(communication_timer);

    let king_answer: Option<Vec<Vec<F>>> = received_shares.map(|numden_shares: Vec<Vec<F>>| {
        // nx(m/l) -> (m/l)xn
        debug_assert_eq!(numden_shares.len(), pp.n, "Mismatch of size in d_pp");
        let dpp_timer = start_timer!(|| "DPP");
        let numden_shares = transpose(numden_shares);

        // Unpack the secrets
        // (m/l)xn -> m
        // iterate over pxss_shares, unpack to get a vector and append all the vectors
        let mut numden: Vec<F> = numden_shares.iter().flat_map(|x| pp.unpack2(&x)).collect();

        for i in 0..numden.len() / 2 {
            let den = numden[i + numden.len() / 2].inverse().unwrap();
            numden[i] *= den;
        }

        numden.truncate(numden.len() / 2);

        // Compute the partial products across pxss
        for i in 1..numden.len() {
            let last = numden[i - 1];
            numden[i] *= last;
        }

        // Pack the secrets
        // m -> (m/l)xn
        // (m/l)xl -> (m/l)xn
        let pp_numden_shares = pack_vec(&numden, pp);
        drop(numden);

        // send shares to parties
        // (m/l)xn -> nx(m/l)
        let pp_numden_shares = transpose(pp_numden_shares);
        end_timer!(dpp_timer);
        pp_numden_shares
    });

    let communication_timer = start_timer!(|| "ComFromKing");
    let mut pp_numden_rand = Net::recv_from_king(king_answer);
    end_timer!(communication_timer);

    // Finally, remove the ranomness in the partial products
    // multiply all entries of pp_pxss by of s
    // do degree reduction
    let dpp_rand_timer = start_timer!(|| "DppRand");
    pp_numden_rand.iter_mut().for_each(|x| *x *= sinv);
    end_timer!(dpp_rand_timer);
    let pp_numden = deg_red(pp_numden_rand, pp); //packed shares of partial products

    pp_numden
}
