use ark_bls12_377::Fr;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand};
use dist_primitives::dmsm::d_msm;
use dist_primitives::dmsm::packexp_from_public;
use mpc_net::{LocalTestNet as Net, MpcNet, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub async fn d_msm_test<G: CurveGroup, Net: MpcNet>(
    pp: &PackedSharingParams<G::ScalarField>,
    dom: &Radix2EvaluationDomain<G::ScalarField>,
    net: &mut Net,
) {
    // let m = pp.l*4;
    // let case_timer = start_timer!(||"affinemsm_test");
    let mbyl: usize = dom.size() / pp.l;
    println!(
        "m: {}, mbyl: {}, party_id: {}",
        dom.size(),
        mbyl,
        net.party_id()
    );

    let rng = &mut ark_std::test_rng();

    let mut y_pub: Vec<G::ScalarField> = Vec::new();
    let mut x_pub: Vec<G> = Vec::new();

    for _ in 0..dom.size() {
        y_pub.push(G::ScalarField::rand(rng));
        x_pub.push(G::rand(rng));
    }

    let x_share: Vec<G> = x_pub
        .chunks(pp.l)
        .map(|s| packexp_from_public(s, pp)[net.party_id() as usize])
        .collect();

    let y_share: Vec<G::ScalarField> = y_pub
        .chunks(pp.l)
        .map(|s| pp.pack_from_public(s.to_vec())[net.party_id() as usize])
        .collect();

    let x_pub_aff: Vec<G::Affine> = x_pub.iter().map(|s| (*s).into()).collect();
    let x_share_aff: Vec<G::Affine> =
        x_share.iter().map(|s| (*s).into()).collect();

    // Will be comparing against this in the end
    let nmsm = start_timer!(|| "Ark msm");
    let should_be_output =
        G::msm(x_pub_aff.as_slice(), y_pub.as_slice()).unwrap();
    end_timer!(nmsm);

    let dmsm = start_timer!(|| "Distributed msm");
    let output = d_msm::<G, Net>(
        &x_share_aff,
        &y_share,
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();
    end_timer!(dmsm);

    if net.is_king() {
        assert_eq!(should_be_output, output);
    }
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp(None).init();

    let network = Net::new_local_testnet(8).await.unwrap();

    network
        .simulate_network_round((), |mut net, _| async move {
            let pp = PackedSharingParams::<Fr>::new(2);
            let dom = Radix2EvaluationDomain::<Fr>::new(32768).unwrap();
            d_msm_test::<ark_bls12_377::G1Projective, _>(&pp, &dom, &mut net)
                .await;
        })
        .await;
}
