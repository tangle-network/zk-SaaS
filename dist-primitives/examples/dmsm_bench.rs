use ark_bls12_377::Fr;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand, Zero};
use dist_primitives::{dmsm::d_msm, Opt};
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

    let mut y_share: Vec<G::ScalarField> = vec![G::ScalarField::zero(); dom.size()];
    let mut x_share: Vec<G> = vec![G::zero(); dom.size()];

    for i in 0..dom.size() {
        y_share[i] = G::ScalarField::rand(rng);
        x_share[i] = G::rand(rng);
    }

    let x_share_aff: Vec<G::Affine> = x_share.iter().map(|s| s.clone().into()).collect();

    let dmsm = start_timer!(|| "Distributed msm");
    d_msm::<G>(&x_share_aff, &y_share, pp);
    end_timer!(dmsm);
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opt = Opt::from_args();

    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    let pp = PackedSharingParams::<Fr>::new(opt.l);
    for i in 10..20 {
        let dom = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();
        println!("domain size: {}", dom.size());
        d_msm_test::<ark_bls12_377::G1Projective>(&pp, &dom);
    }

    Net::deinit();
}
