use ark_bls12_377::Fr;
use ark_ff::PrimeField;
use dist_primitives::Opt;
use groth16::{ext_wit::d_ext_wit, ConstraintDomain};
use mpc_net::{MpcMultiNet as Net, MpcNet};
use rand::Rng;
use secret_sharing::pss::PackedSharingParams;
use structopt::StructOpt;

fn groth_ext_wit<F: PrimeField, R: Rng>(
    rng: &mut R,
    cd: &ConstraintDomain<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<F> {
    let mut p_eval: Vec<F> = vec![F::rand(rng); cd.m / pp.l];
    // Shares of P, Q, W drop from the sky
    // P = a_i . u_i
    // Q = a_i ⋅ v_i
    // W = a_i ⋅ w_i

    for i in 1..p_eval.len() {
        p_eval[i] = p_eval[i - 1].double();
    }
    let q_eval: Vec<F> = p_eval.clone();
    let w_eval: Vec<F> = p_eval.clone();

    d_ext_wit(p_eval, q_eval, w_eval, rng, pp, cd)
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opt = Opt::from_args();

    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);

    let rng = &mut ark_std::test_rng();
    for i in 14..15 {
        let pp = PackedSharingParams::<Fr>::new(opt.l);
        let cd = ConstraintDomain::<Fr>::new(1 << i);
        groth_ext_wit(rng, &cd, &pp);
    }

    Net::deinit();
}
