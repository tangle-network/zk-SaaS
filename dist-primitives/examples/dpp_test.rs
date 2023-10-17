use ark_bls12_377::Fr;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use dist_primitives::{
    channel::MpcSerNet,
    dpp::d_pp,
    utils::pack::{pack_vec, transpose},
};
use mpc_net::{LocalTestNet as Net, MpcNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn d_pp_test<F: FftField + PrimeField, Net: MpcNet>(
    pp: &PackedSharingParams<F>,
    dom: &Radix2EvaluationDomain<F>,
    net: &mut Net,
) {
    // We apply FFT on this vector
    // let mut x = vec![F::ONE; cd.m];
    let mut x: Vec<F> = Vec::new();
    for i in 0..dom.size() {
        x.push(F::from((i + 1) as u64));
    }

    // Output to test against
    let should_be_output = vec![F::one(); dom.size()];

    // pack x
    let px = transpose(pack_vec(&x, pp));

    let px_share = px[net.party_id() as usize].clone();
    let pp_px_share = d_pp(
        px_share.clone(),
        px_share.clone(),
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();

    // Send to king who reconstructs and checks the answer
    net.send_to_king(&pp_px_share, MultiplexedStreamID::One)
        .await
        .unwrap()
        .map(|pp_px_shares| {
            let pp_px_shares = transpose(pp_px_shares);

            let pp_px: Vec<F> = pp_px_shares
                .into_iter()
                .flat_map(|x| pp.unpack(x))
                .collect();

            if net.is_king() {
                debug_assert_eq!(should_be_output, pp_px);
            }
        });
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp(None).init();

    let network = Net::new_local_testnet(4).await.unwrap();
    network
        .simulate_network_round((), |mut net, _| async move {
            let pp = PackedSharingParams::<Fr>::new(2);
            let cd = Radix2EvaluationDomain::<Fr>::new(1 << 15).unwrap();
            d_pp_test::<Fr, _>(&pp, &cd, &mut net).await;
        })
        .await;
}
