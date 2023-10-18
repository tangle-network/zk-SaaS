use ark_ff::{FftField, PrimeField};
use mpc_net::{MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

use crate::channel::MpcSerNet;

use super::pack::transpose;

/// Reduces the degree of a poylnomial with the help of king
pub async fn deg_red<F: FftField + PrimeField, Net: MpcSerNet>(
    px: Vec<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MpcNetError> {
    let received_shares = net.send_to_king(&px, sid).await?;
    let king_answer: Option<Vec<Vec<F>>> =
        received_shares.map(|px_shares: Vec<Vec<F>>| {
            let mut px_shares = transpose(px_shares);
            for px_share in &mut px_shares {
                pp.unpack2_in_place(px_share);
                pp.pack_from_public_in_place(px_share);
            }
            transpose(px_shares)
        });

    net.recv_from_king(king_answer, sid).await
}
