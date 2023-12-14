use std::sync::Arc;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::BigInt;
use ark_groth16::{Groth16, Proof};
use ark_poly::Radix2EvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::{cfg_chunks, cfg_into_iter, end_timer, start_timer, Zero};

use groth16::qap::qap;
use groth16::{ext_wit, qap};
use log::debug;
use mpc_net::{LocalTestNet as Net, MpcNet, MultiplexedStreamID};

use rand::SeedableRng;
use secret_sharing::pss::PackedSharingParams;

use groth16::proving_key::PackedProvingKeyShare;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

async fn dsha256<E, Net>(
    pp: &PackedSharingParams<E::ScalarField>,
    crs_share: &PackedProvingKeyShare<E>,
    qap_share: qap::PackedQAPShare<
        E::ScalarField,
        Radix2EvaluationDomain<E::ScalarField>,
    >,
    a_share: &[E::ScalarField],
    ax_share: &[E::ScalarField],
    net: &Net,
) -> (E::G1, E::G2, E::G1)
where
    E: Pairing,
    Net: MpcNet,
{
    let h_share = ext_wit::circom_h(qap_share, pp, &net).await.unwrap();
    let msm_section = start_timer!(|| "MSM operations");
    // Compute msm while dropping the base vectors as they are not used again
    let compute_a = start_timer!(|| "Compute A");
    let pi_a_share = groth16::prove::A::<E> {
        L: Default::default(),
        N: Default::default(),
        r: E::ScalarField::zero(),
        pp,
        S: &crs_share.s,
        a: a_share,
    }
    .compute(net, MultiplexedStreamID::Zero)
    .await
    .unwrap();
    end_timer!(compute_a);

    let compute_b = start_timer!(|| "Compute B");
    let pi_b_share: E::G2 = groth16::prove::B::<E> {
        Z: Default::default(),
        K: Default::default(),
        s: E::ScalarField::zero(),
        pp,
        V: &crs_share.v,
        a: a_share,
    }
    .compute(net, MultiplexedStreamID::Zero)
    .await
    .unwrap();
    end_timer!(compute_b);

    let compute_c = start_timer!(|| "Compute C");
    let pi_c_share = groth16::prove::C::<E> {
        W: &crs_share.w,
        U: &crs_share.u,
        A: pi_a_share,
        M: Default::default(),
        r: E::ScalarField::zero(),
        s: E::ScalarField::zero(),
        pp,
        H: &crs_share.h,
        a: a_share,
        ax: ax_share,
        h: &h_share,
    }
    .compute(net)
    .await
    .unwrap();
    end_timer!(compute_c);

    end_timer!(msm_section);

    // Send pi_a_share, pi_b_share, pi_c_share to client
    (pi_a_share, pi_b_share, pi_c_share)
}

fn pack_from_witness<E: Pairing>(
    pp: &PackedSharingParams<E::ScalarField>,
    full_assignment: Vec<E::ScalarField>,
) -> Vec<Vec<E::ScalarField>> {
    let rng = &mut ark_std::test_rng();
    let packed_assignments = cfg_chunks!(full_assignment, pp.l)
        .map(|chunk| {
            let secrets = if chunk.len() < pp.l {
                let mut secrets = chunk.to_vec();
                secrets.resize(pp.l, E::ScalarField::zero());
                secrets
            } else {
                chunk.to_vec()
            };
            pp.pack(secrets, rng)
        })
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
    let qap =
        qap::<Bn254Fr, Radix2EvaluationDomain<_>>(&matrices, &full_assignment)
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
    let qap_shares = qap.pss(&pp);
    let pp = PackedSharingParams::new(pp.l);
    let crs_shares =
        PackedProvingKeyShare::<Bn254>::pack_from_arkworks_proving_key(
            &pk, pp,
        );
    let crs_shares = Arc::new(crs_shares);
    let qap_shares = Arc::new(qap_shares);
    let aux_assignment = &full_assignment[num_inputs..];
    let ax_shares = pack_from_witness::<Bn254>(&pp, aux_assignment.to_vec());
    let a_shares =
        pack_from_witness::<Bn254>(&pp, full_assignment[1..].to_vec());
    let network = Net::new_local_testnet(pp.n).await.unwrap();

    let result = network
        .simulate_network_round(
            (crs_shares, pp, a_shares, ax_shares, qap_shares),
            |net, (crs_shares, pp, a_shares, ax_shares, qap_shares)| async move {
                let idx = net.party_id() as usize;
                let crs_share =
                    crs_shares.get(idx).unwrap();
                let a_share = &a_shares[idx];
                let ax_share = &ax_shares[idx];
                let qap_share = qap_shares[idx].clone();
                dsha256(&pp, crs_share, qap_share, a_share, ax_share, &net).await
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
        c: c.into_affine(),
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
