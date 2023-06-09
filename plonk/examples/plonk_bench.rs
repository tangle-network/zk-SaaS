use ark_ec::{bls12::Bls12, pairing::Pairing};
use dist_primitives::Opt;
use log::debug;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use plonk::{dplonk::d_plonk_test, PlonkDomain};

use ark_bls12_377;
use secret_sharing::pss::PackedSharingParams;
use structopt::StructOpt;
type BlsE = Bls12<ark_bls12_377::Config>;
type BlsFr = <Bls12<ark_bls12_377::Config> as Pairing>::ScalarField;

fn main() {
    debug!("Start");

    env_logger::builder().format_timestamp(None).init();
    let opt = Opt::from_args();
    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    let pd = PlonkDomain::<BlsFr>::new(opt.m);
    let pp = PackedSharingParams::<BlsFr>::new(opt.l);
    d_plonk_test::<BlsE>(&pd, &pp);

    if Net::am_king() {
        println!("Stats: {:#?}", Net::stats());
    }

    Net::deinit();
    debug!("Done");
}
