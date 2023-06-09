use ark_bls12_377::Bls12_377;
use ark_bls12_377::Fr;
use ark_ec::pairing::Pairing;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer};
use dist_primitives::Opt;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use plonk::dpoly_commit::PackPolyCk;
use plonk::poly_commit::PolyCk;
use secret_sharing::pss::PackedSharingParams;
use structopt::StructOpt;

pub fn d_poly_commit_test<E: Pairing>(
    pp: &PackedSharingParams<E::ScalarField>,
    dom: &Radix2EvaluationDomain<E::ScalarField>,
) {
    let mbyl: usize = dom.size() / pp.l;
    println!("m: {}, mbyl: {}", dom.size(), mbyl);

    let rng = &mut ark_std::test_rng();

    let pck = PackPolyCk::<E>::new(dom.size(), rng, pp);
    let peval_share: Vec<E::ScalarField> =
        (0..mbyl).map(|i| E::ScalarField::from(i as u32)).collect();

    let dmsm = start_timer!(|| "Distributed poly_commit");
    pck.commit(&peval_share, pp);
    end_timer!(dmsm);

    let dmsm = start_timer!(|| "Distributed commit_open");
    pck.open(&peval_share, E::ScalarField::from(123 as u32), dom, pp);
    end_timer!(dmsm);

    if Net::am_king() {
        let ck = PolyCk::<E>::new(dom.size(), rng);
        let pevals: Vec<E::ScalarField> = (0..dom.size())
            .map(|i| E::ScalarField::from(i as u32))
            .collect();
        let nmsm = start_timer!(|| "Ark poly_commit");
        ck.commit(&pevals);
        end_timer!(nmsm);
        let nmsm = start_timer!(|| "Ark commit_open");
        ck.open(&pevals, E::ScalarField::from(123 as u32), dom);
        end_timer!(nmsm);
    }
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opt = Opt::from_args();

    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    let pp = PackedSharingParams::<Fr>::new(opt.l);
    let dom = Radix2EvaluationDomain::<Fr>::new(opt.m).unwrap();
    d_poly_commit_test::<Bls12_377>(&pp, &dom);

    Net::deinit();
}
