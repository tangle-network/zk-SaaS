use std::sync::Arc;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::BigInt;
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_groth16::{Groth16, Proof};
use ark_poly::Radix2EvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{cfg_chunks, cfg_into_iter, end_timer, start_timer, Zero};

use dist_primitives::dmsm;
use log::debug;
use mpc_net::{LocalTestNet as Net, MpcNet, MultiplexedStreamID};

use rand::SeedableRng;
use secret_sharing::pss::PackedSharingParams;

use groth16::proving_key::PackedProvingKeyShare;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

async fn dsha256<E: Pairing, Net: MpcNet>(
    pp: &PackedSharingParams<E::ScalarField>,
    crs_share: &PackedProvingKeyShare<E>,
    a_share: &[E::ScalarField],
    h_share: &[E::ScalarField],
    net: &mut Net,
) -> (E::G1, E::G2, E::G1) {
    debug!(
        "s:{}, v:{}, h:{}, w:{}, u:{}, a_share:{}, h_share:{}",
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
    let pi_a_share: E::G1 =
        dmsm::d_msm(&crs_share.s, a_share, pp, net, MultiplexedStreamID::One)
            .await
            .unwrap();
    let pi_b_share: E::G2 =
        dmsm::d_msm(&crs_share.v, a_share, pp, net, MultiplexedStreamID::One)
            .await
            .unwrap();
    // let pi_c_share1: E::G1 =
    //     dmsm::d_msm(&crs_share.h, a_share, pp, net, MultiplexedStreamID::One)
    //         .await
    //         .unwrap();
    // let pi_c_share2: E::G1 =
    //     dmsm::d_msm(&crs_share.w, a_share, pp, net, MultiplexedStreamID::One)
    //         .await
    //         .unwrap();
    // let pi_c_share3: E::G1 =
    //     dmsm::d_msm(&crs_share.u, h_share, pp, net, MultiplexedStreamID::One)
    //         .await
    //         .unwrap();
    // let pi_c_share: E::G1 = pi_c_share1 + pi_c_share2 + pi_c_share3; //Additive notation for groups
    end_timer!(msm_section);

    // Send pi_a_share, pi_b_share, pi_c_share to client
    let pi_c_share = E::G1::zero();
    (pi_a_share, pi_b_share, pi_c_share)
}

fn pack_from_witness<E: Pairing>(
    pp: &PackedSharingParams<E::ScalarField>,
    full_assignment: Vec<E::ScalarField>,
) -> Vec<Vec<E::ScalarField>> {
    let packed_assignments = cfg_chunks!(full_assignment, pp.l)
        .map(|chunk| pp.pack_from_public(chunk.to_vec()))
        .collect::<Vec<_>>();

    cfg_into_iter!(0..pp.n)
        .map(|i| {
            cfg_into_iter!(0..packed_assignments.len())
                .map(|j| packed_assignments[j][i])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp(None).init();

    let cfg = CircomConfig::<Bn254>::new(
        "./fixtures/sha256/sha256_js/sha256.wasm",
        "./fixtures/sha256/sha256.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);
    let rng = &mut ark_std::rand::rngs::StdRng::from_seed([42u8; 32]);
    builder.push_input("a", 1);
    builder.push_input("b", 2);
    let circuit = builder.setup();
    let (pk, vk) =
        Groth16::<Bn254, CircomReduction>::circuit_specific_setup(circuit, rng)
            .unwrap();

    let circom = builder.build().unwrap();
    let full_assignment = circom.witness.clone().unwrap();
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    circom.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    let matrices = cs.to_matrices().unwrap();

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;
    let h = CircomReduction::witness_map_from_matrices::<
        Bn254Fr,
        Radix2EvaluationDomain<_>,
    >(&matrices, num_inputs, num_constraints, &full_assignment)
    .unwrap();

    let r = Bn254Fr::zero();
    let s = Bn254Fr::zero();
    let arkworks_proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &full_assignment,
    ).unwrap();

    let pp = PackedSharingParams::new(2);
    let pp_g1 = PackedSharingParams::new(pp.l);
    let pp_g2 = PackedSharingParams::new(pp.l);
    let crs_shares =
        PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(
            &pk, pp_g1, pp_g2,
        );
    let crs_shares = Arc::new(crs_shares);
    let a_shares =
        pack_from_witness::<Bn254>(&pp, full_assignment[1..].to_vec());
    let h_shares = pack_from_witness::<Bn254>(&pp, h);
    let network = Net::new_local_testnet(pp.n).await.unwrap();

    let result = network
        .simulate_network_round(
            (crs_shares, pp, a_shares, h_shares),
            |mut net, (crs_shares, pp, a_shares, h_shares)| async move {
                let crs_share =
                    crs_shares.get(net.party_id() as usize).unwrap();
                let a_share = &a_shares[net.party_id() as usize];
                let h_share = &h_shares[net.party_id() as usize];
                dsha256(&pp, crs_share, a_share, h_share, &mut net).await
            },
        )
        .await;
    let (mut a, mut b, c) = result[0];
    // These elements are needed to construct the full proof, they are part of the proving key.
    // however, we can just send these values to the client, not the full proving key.
    a += pk.a_query[0] + vk.alpha_g1;
    b += pk.b_g2_query[0] + vk.beta_g2;
    debug!("a:{}", a);
    debug!("b:{}", b);
    debug!("c:{}", c);
    debug!("------------");
    debug!("arkworks_a:{}", arkworks_proof.a);
    debug!("arkworks_b:{}", arkworks_proof.b);
    debug!("arkworks_c:{}", arkworks_proof.c);

    let pvk = ark_groth16::verifier::prepare_verifying_key(&vk);
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &[BigInt!(
            "72587776472194017031617589674261467945970986113287823188107011979"
        )
        .into()],
        &arkworks_proof,
    )
    .unwrap();

    assert!(verified, "Arkworks Proof verification failed!");
    let proof = Proof::<Bn254> {
        a: a.into_affine(),
        b: b.into_affine(),
        // TODO: replace this with the actual c from our computation
        c: arkworks_proof.c,
    };
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &[BigInt!(
            "72587776472194017031617589674261467945970986113287823188107011979"
        )
        .into()],
        &proof,
    )
    .unwrap();
    assert!(verified, "Proof verification failed!");
}
