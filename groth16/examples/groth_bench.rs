use ark_ec::{bls12::Bls12, pairing::Pairing};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer};
use dist_primitives::{dmsm, Opt};
use log::debug;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use rand::Rng;
use secret_sharing::pss::PackedSharingParams;
use structopt::StructOpt;

use ark_bls12_377;
type BlsE = Bls12<ark_bls12_377::Config>;
type BlsFr = <Bls12<ark_bls12_377::Config> as Pairing>::ScalarField;

use groth16::{
    ext_wit::groth_ext_wit, proving_key::PackProvingKeyShare, ConstraintDomain,
};

fn dgroth<E: Pairing>(
    pp: &PackedSharingParams<E::ScalarField>,
    cd: &ConstraintDomain<E::ScalarField>,
) {
    // Add preprocessing vectors of size 4m/l
    // process u and v to get ready for multiplication

    // Field operations
    // u, v, w -- m/l + m/l + m/l
    // Compute IFFT(u)
    // Compute FFT(u)
    // Compute IFFT(v)
    // Compute FFT(v)
    // Compute IFFT(w)
    // Compute FFT(w)
    // u, v - 2m/l + 2m/l shares
    // w - 2m/l shares
    // t - 2m/l shares (Can be dropped in later by king so not contributing to memory)

    // Former can be avoided if client provides 2Q evaluations of u,v,w instead of Q evaluations
    // Computing h
    // Compute h = (u.v - w).t -- 2m/l shares
    // Send to king to pack desired coefficients of h

    // Group operations
    // Packed CRS drops in from the sky
    // Do 5 MSMs to obtain shares of A, B and C
    // Done

    let rng = &mut ark_std::test_rng();
    let crs_share: PackProvingKeyShare<E> =
        PackProvingKeyShare::<E>::rand(rng, cd.m, pp);
    let a_share: Vec<E::ScalarField> =
        vec![E::ScalarField::rand(rng); crs_share.s.len()];

    let h_share: Vec<E::ScalarField> = groth_ext_wit(rng, cd, pp);

    println!(
        "s:{}, v:{}, h:{}, w:{}, u:{}, a:{}, h:{}",
        crs_share.s.len(),
        crs_share.v.len(),
        crs_share.h.len(),
        crs_share.w.len(),
        crs_share.u.len(),
        a_share.len(),
        h_share.len()
    );

    let msm_section = start_timer!(|| "MSM operations");
    // Compute msm while dropping the base vectors as they are not used again
    let _pi_a_share: E::G1 = dmsm::d_msm(&crs_share.s, &a_share, pp);
    println!("s done");
    let _pi_b_share: E::G2 = dmsm::d_msm(&crs_share.v, &a_share, pp);
    println!("v done");
    let _pi_c_share1: E::G1 = dmsm::d_msm(&crs_share.h, &a_share, pp);
    println!("h done");
    let _pi_c_share2: E::G1 = dmsm::d_msm(&crs_share.w, &a_share, pp);
    println!("w done");
    let _pi_c_share3: E::G1 = dmsm::d_msm(&crs_share.u, &h_share, pp);
    println!("u done");
    let _pi_c_share: E::G1 = _pi_c_share1 + _pi_c_share2 + _pi_c_share3; //Additive notation for groups
                                                                         // Send _pi_a_share, _pi_b_share, _pi_c_share to client
    end_timer!(msm_section);

    debug!("Done");
}

fn main() {
    env_logger::builder().format_timestamp(None).init();

    let opt = Opt::from_args();

    Net::init_from_file(opt.input.to_str().unwrap(), opt.id);
    let pp = PackedSharingParams::<BlsFr>::new(opt.l);
    let cd = ConstraintDomain::<BlsFr>::new(opt.m);
    dgroth::<BlsE>(&pp, &cd);
    if Net::am_king() {
        println!("Stats: {:#?}", Net::stats());
    }

    Net::deinit();
}
