use ark_ec::{bls12::Bls12, pairing::Pairing};
use plonk::{localplonk::localplonk, PlonkDomain};

use ark_bls12_377;
use structopt::StructOpt;
type BlsE = Bls12<ark_bls12_377::Config>;
type BlsFr = <Bls12<ark_bls12_377::Config> as Pairing>::ScalarField;

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
struct Opt {
    /// size
    pub m: usize,
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let opt = Opt::from_args();
    let cd = PlonkDomain::<BlsFr>::new(opt.m);
    localplonk::<BlsE>(&cd);
}
