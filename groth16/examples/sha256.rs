use std::sync::Arc;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_groth16::Groth16;
use ark_poly::Radix2EvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::Zero;
use ark_std::{cfg_chunks, cfg_into_iter, end_timer, start_timer};
use dist_primitives::dmsm;
use log::debug;
use mpc_net::{LocalTestNet as Net, MpcNet, MultiplexedStreamID};

use secret_sharing::pss::PackedSharingParams;

use groth16::{
    ext_wit::d_ext_wit, proving_key::PackedProvingKeyShare, ConstraintDomain,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

async fn dsha256<E: Pairing, Net: MpcNet>(
    pp: &PackedSharingParams<E::ScalarField>,
    crs_share: &PackedProvingKeyShare<E>,
    qap: groth16::qap::QAP<
        E::ScalarField,
        Radix2EvaluationDomain<E::ScalarField>,
    >,
    a_share: &[E::ScalarField],
    cd: &ConstraintDomain<E::ScalarField>,
    net: &mut Net,
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

    let h_share: Vec<E::ScalarField> =
        d_ext_wit(qap.a, qap.b, qap.c, rng, pp, cd, net)
            .await
            .unwrap();

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
    let _pi_a_share: E::G1 = dmsm::d_msm(
        &crs_share.s,
        &a_share[..crs_share.s.len()],
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();
    println!("s done");
    let _pi_b_share: E::G2 = dmsm::d_msm(
        &crs_share.v,
        &a_share[..crs_share.v.len()],
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();
    println!("v done");
    let _pi_c_share1: E::G1 = dmsm::d_msm(
        &crs_share.h,
        &a_share[..crs_share.h.len()],
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();
    println!("h done");
    let _pi_c_share2: E::G1 = dmsm::d_msm(
        &crs_share.w,
        &a_share[..crs_share.w.len()],
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();
    println!("w done");
    let _pi_c_share3: E::G1 = dmsm::d_msm(
        &crs_share.u,
        &h_share[..crs_share.u.len()],
        pp,
        net,
        MultiplexedStreamID::One,
    )
    .await
    .unwrap();
    println!("u done");
    let _pi_c_share: E::G1 = _pi_c_share1 + _pi_c_share2 + _pi_c_share3; //Additive notation for groups
                                                                         // Send _pi_a_share, _pi_b_share, _pi_c_share to client
    end_timer!(msm_section);

    debug!("Done");
}

fn pack_from_witness<E: Pairing>(
    n: usize,
    pp: &PackedSharingParams<E::ScalarField>,
    mut full_assignment: Vec<E::ScalarField>,
) -> Vec<Vec<E::ScalarField>> {
    // ensure that full assignment is divisible by l
    // by padding with zeros if necessary.
    let full_assignment_len = full_assignment.len();
    let remainder = full_assignment_len % pp.l;
    let full_assignment = if remainder != 0 {
        // push zero element to make it divisible by l
        full_assignment
            .extend_from_slice(&vec![E::ScalarField::zero(); pp.l - remainder]);
        full_assignment
    } else {
        full_assignment
    };
    let packed_assignments = cfg_chunks!(full_assignment, pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>();

    cfg_into_iter!(0..n)
        .map(|i| {
            cfg_into_iter!(0..packed_assignments.len())
                .map(|j| packed_assignments[j][i])
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp(None).init();

    let n = 8;
    let cfg = CircomConfig::<Bn254>::new(
        "../fixtures/sha256/sha256_js/sha256.wasm",
        "../fixtures/sha256/sha256.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    let rng = &mut ark_std::rand::thread_rng();
    builder.push_input("a", 3);
    builder.push_input("b", 11);
    let circuit = builder.setup();
    let (pk, _vk) =
        Groth16::<Bn254, CircomReduction>::circuit_specific_setup(circuit, rng)
            .unwrap();

    let circom = builder.build().unwrap();
    let full_assignment = circom.witness.clone().unwrap();
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    circom.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    let matrices = cs.to_matrices().unwrap();

    let qap = groth16::qap::qap::<Bn254Fr, Radix2EvaluationDomain<_>>(
        &matrices,
        &full_assignment,
    )
    .unwrap();
    let pp_g1 = PackedSharingParams::new(2);
    let pp_g2 = PackedSharingParams::new(2);
    let crs_shares =
        PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(
            &pk, n, pp_g1, pp_g2,
        );
    let crs_shares = Arc::new(crs_shares);
    let pp = PackedSharingParams::<Bn254Fr>::new(2);
    let a_shares = pack_from_witness::<Bn254>(n, &pp, full_assignment);
    let network = Net::new_local_testnet(n).await.unwrap();

    network
        .simulate_network_round(
            (crs_shares, pp, qap, a_shares),
            |mut net, (crs_shares, pp, qap, a_shares)| async move {
                let cd = ConstraintDomain::<Bn254Fr>::new(32768);
                log::debug!("Running for party: {}", net.party_id());
                let crs_share =
                    crs_shares.get(net.party_id() as usize).unwrap();
                let a_share = a_shares[net.party_id() as usize].clone();
                dsha256(&pp, crs_share, qap, &a_share, &cd, &mut net).await;
            },
        )
        .await;
}
