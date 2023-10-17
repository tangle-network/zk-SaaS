use ark_bls12_377::Fr;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use dist_primitives::{
    channel::MpcSerNet,
    dfft::{d_fft, fft_in_place_rearrange},
    utils::pack::transpose,
};
use mpc_net::{LocalTestNet as Net, MpcNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn d_fft_test<F: FftField + PrimeField, Net: MpcNet>(
    pp: &PackedSharingParams<F>,
    dom: &Radix2EvaluationDomain<F>,
    net: &Net,
) {
    let mbyl: usize = dom.size() / pp.l;
    // We apply FFT on this vector
    // let mut x = vec![F::ONE; cd.m];
    let mut x: Vec<F> = Vec::new();
    for i in 0..dom.size() {
        x.push(F::from(i as u64));
    }

    // Output to test against
    let should_be_output = dom.fft(&x);

    fft_in_place_rearrange(&mut x);
    let mut pcoeff: Vec<Vec<F>> = Vec::new();
    for i in 0..mbyl {
        pcoeff
            .push(x.iter().skip(i).step_by(mbyl).cloned().collect::<Vec<_>>());
        pp.pack_from_public_in_place(&mut pcoeff[i]);
    }

    let pcoeff_share = pcoeff
        .iter()
        .map(|x| x[net.party_id() as usize])
        .collect::<Vec<_>>();

    // Rearranging x

    let peval_share = d_fft(
        pcoeff_share,
        false,
        1,
        false,
        dom,
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();

    // Send to king who reconstructs and checks the answer
    net.send_to_king(&peval_share, MultiplexedStreamID::One)
        .await
        .unwrap()
        .map(|peval_shares| {
            let peval_shares = transpose(peval_shares);

            let pevals: Vec<F> = peval_shares
                .into_iter()
                .flat_map(|x| pp.unpack(x))
                .rev()
                .collect();

            if net.is_king() {
                assert_eq!(should_be_output, pevals);
            }
        });
}

#[tokio::main]
pub async fn main() {
    env_logger::builder().format_timestamp(None).init();
    let network = Net::new_local_testnet(8).await.unwrap();
    network
        .simulate_network_round((), |net, _| async move {
            let pp = PackedSharingParams::<Fr>::new(2);
            let dom = Radix2EvaluationDomain::<Fr>::new(1024).unwrap();
            d_fft_test::<Fr, _>(&pp, &dom, &net).await;
        })
        .await;
}
