use ark_bls12_377::Fr;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand};
use dist_primitives::dmsm::dmsm::packexp_from_public;
use dist_primitives::{dmsm::dmsm::d_msm, Opt};
use mpc_net::{MpcMultiNet as Net, MpcNet};
use secret_sharing::pss::PackedSharingParams;
use structopt::StructOpt;

pub fn d_msm_test<G: CurveGroup>(
    pp: &PackedSharingParams<G::ScalarField>,
    dom: &Radix2EvaluationDomain<G::ScalarField>,
) {
    // let m = pp.l*4;
    // let case_timer = start_timer!(||"affinemsm_test");
    let mbyl: usize = dom.size() / pp.l;
    println!("m: {}, mbyl: {}", dom.size(), mbyl);

    let rng = &mut ark_std::test_rng();

    let mut y_pub: Vec<G::ScalarField> = Vec::new();
    let mut x_pub: Vec<G> = Vec::new();

    for _ in 0..dom.size() {
        y_pub.push(G::ScalarField::rand(rng));
        x_pub.push(G::rand(rng));
    }

    let x_share: Vec<G> = x_pub
        .chunks(pp.l)
        .map(|s| packexp_from_public(&s.to_vec(), &pp)[Net::party_id()])
        .collect();

    let y_share: Vec<G::ScalarField> = y_pub
        .chunks(pp.l)
        .map(|s| pp.pack_from_public(&s.to_vec())[Net::party_id()])
        .collect();

    let x_pub_aff: Vec<G::Affine> = x_pub.iter().map(|s| s.clone().into()).collect();
    let x_share_aff: Vec<G::Affine> = x_share.iter().map(|s| s.clone().into()).collect();

    // Will be comparing against this in the end
    let nmsm = start_timer!(|| "Ark msm");
    let should_be_output = G::msm(&x_pub_aff.as_slice(), &y_pub.as_slice()).unwrap();
    end_timer!(nmsm);

    let dmsm = start_timer!(|| "Distributed msm");
    let output = d_msm::<G>(&x_share_aff, &y_share, pp);
    end_timer!(dmsm);

    if Net::am_king() {
        assert_eq!(should_be_output, output);
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opt = Opt::from_args();

    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    let pp = PackedSharingParams::<Fr>::new(opt.l);
    let dom = Radix2EvaluationDomain::<Fr>::new(opt.m).unwrap();
    d_msm_test::<ark_bls12_377::G1Projective>(&pp, &dom);

    Net::deinit();
}
