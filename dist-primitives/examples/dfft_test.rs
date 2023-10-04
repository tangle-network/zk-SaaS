use ark_bls12_377::Fr;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer};
use dist_primitives::{
    channel::MpcSerNet,
    dfft::{d_fft, fft_in_place_rearrange},
    utils::pack::transpose,
    Opt,
};
use mpc_net::{LocalTestNet as Net, MpcNet};
use secret_sharing::pss::PackedSharingParams;
use structopt::StructOpt;

pub async fn d_fft_test<F: FftField + PrimeField, Net: MpcNet>(
    pp: &PackedSharingParams<F>,
    dom: &Radix2EvaluationDomain<F>,
    net: &mut Net,
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

    let pcoeff_share =
        pcoeff.iter().map(|x| x[net.party_id()]).collect::<Vec<_>>();

    // Rearranging x
    let myfft_timer = start_timer!(|| "Distributed FFT");

    let peval_share = d_fft(pcoeff_share, false, 1, false, dom, pp, net).await;
    end_timer!(myfft_timer);

    // Send to king who reconstructs and checks the answer
    net.send_to_king(&peval_share).await.map(|peval_shares| {
        let peval_shares = transpose(peval_shares);

        let mut pevals: Vec<F> = peval_shares
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect();
        pevals.reverse(); // todo: implement such that we avoid this reverse

        if net.is_king() {
            assert_eq!(should_be_output, pevals);
        }
    });
}

#[tokio::main]
pub async fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opt = Opt::from_args();

    let mut network = Net::new_from_path(opt.input.to_str().unwrap(), opt.id)
        .await
        .unwrap();
    network.init().await;

    let pp = PackedSharingParams::<Fr>::new(opt.l);
    let dom = Radix2EvaluationDomain::<Fr>::new(opt.m).unwrap();
    debug_assert_eq!(
        dom.size(),
        opt.m,
        "Failed to obtain domain of size {}",
        opt.m
    );
    d_fft_test::<ark_bls12_377::Fr, _>(&pp, &dom, &mut network).await;

    network.deinit();
}
