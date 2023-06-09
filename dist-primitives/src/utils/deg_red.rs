use ark_ff::{FftField, PrimeField};
use ark_std::{end_timer, start_timer};
use mpc_net::MpcMultiNet as Net;
use secret_sharing::pss::PackedSharingParams;

use crate::channel::channel::MpcSerNet;

use super::pack::transpose;

/// Reduces the degree of a poylnomial with the help of king
pub fn deg_red<F: FftField + PrimeField>(px: Vec<F>, pp: &PackedSharingParams<F>) -> Vec<F> {
    let communication_timer = start_timer!(|| "ComToKing");
    let received_shares = Net::send_to_king(&px);
    end_timer!(communication_timer);
    let king_answer: Option<Vec<Vec<F>>> = received_shares.map(|px_shares: Vec<Vec<F>>| {
        let repack_shares_timer = start_timer!(|| "Unpack Pack shares");
        let mut px_shares = transpose(px_shares);
        for i in 0..px_shares.len() {
            pp.unpack2_in_place(&mut px_shares[i]);
            pp.pack_from_public_in_place(&mut px_shares[i]);
        }
        end_timer!(repack_shares_timer);
        transpose(px_shares)
    });

    let communication_timer = start_timer!(|| "ComFromKing");
    let got_from_king = Net::recv_from_king(king_answer);
    end_timer!(communication_timer);

    got_from_king
}
