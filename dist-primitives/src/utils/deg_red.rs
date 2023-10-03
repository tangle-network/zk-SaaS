use ark_ff::{FftField, PrimeField};
use ark_std::{end_timer, start_timer};
use secret_sharing::pss::PackedSharingParams;

use crate::channel::MpcSerNet;

use super::pack::transpose;

/// Reduces the degree of a poylnomial with the help of king
pub async fn deg_red<F: FftField + PrimeField, Net: MpcSerNet>(
    px: Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &mut Net,
) -> Vec<F> {
    let communication_timer = start_timer!(|| "ComToKing");
    let received_shares = net.send_to_king(&px).await;
    end_timer!(communication_timer);
    let king_answer: Option<Vec<Vec<F>>> =
        received_shares.map(|px_shares: Vec<Vec<F>>| {
            let repack_shares_timer = start_timer!(|| "Unpack Pack shares");
            let mut px_shares = transpose(px_shares);
            for px_share in &mut px_shares {
                pp.unpack2_in_place(px_share);
                pp.pack_from_public_in_place(px_share);
            }
            end_timer!(repack_shares_timer);
            transpose(px_shares)
        });

    let communication_timer = start_timer!(|| "ComFromKing");
    let got_from_king = net.recv_from_king(king_answer).await;
    end_timer!(communication_timer);

    got_from_king
}
