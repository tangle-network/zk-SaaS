use ark_ff::{FftField, PrimeField};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::SynthesisError;
use ark_std::cfg_into_iter;
use dist_primitives::channel::MpcSerNet;
use dist_primitives::dfft::{d_fft, d_ifft};
use dist_primitives::utils::pack::{pack_vec, transpose};
use mpc_net::{MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

use crate::qap::PackedQAPShare;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub async fn h<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    qap_share: PackedQAPShare<F, D>,
    pp: &PackedSharingParams<F>,
    net: &Net,
) -> Result<Vec<F>, MpcNetError> {
    const CHANNEL0: MultiplexedStreamID = MultiplexedStreamID::Zero;
    const CHANNEL1: MultiplexedStreamID = MultiplexedStreamID::One;
    const CHANNEL2: MultiplexedStreamID = MultiplexedStreamID::Two;

    let domain = qap_share.domain;
    let m = domain.size();
    let domain2 =
        D::new(2 * m).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

    let a_coeff_fut =
        d_ifft(qap_share.a, true, &domain, pp, net, CHANNEL0);
    let b_coeff_fut =
        d_ifft(qap_share.b, true, &domain, pp, net, CHANNEL1);
    let c_coeff_fut =
        d_ifft(qap_share.c, true, &domain, pp, net, CHANNEL2);

    let (a_coeff, b_coeff, c_coeff) =
        tokio::try_join!(a_coeff_fut, b_coeff_fut, c_coeff_fut)?;

    /*
    let p_eval_fut =
        d_fft(p_coeff, false, 1, false, &domain2, pp, net, CHANNEL0);
    let q_eval_fut =
        d_fft(q_coeff, false, 1, false, &domain2, pp, net, CHANNEL1);
    let w_eval_fut =
        d_fft(w_coeff, false, 1, false, &domain2, pp, net, CHANNEL2);

    let (p_eval, q_eval, w_eval) =
        tokio::try_join!(p_eval_fut, q_eval_fut, w_eval_fut)?;

    let received_p_shares_fut = net.send_to_king(&p_eval, CHANNEL0);
    let received_q_shares_fut = net.send_to_king(&q_eval, CHANNEL1);
    let received_w_shares_fut = net.send_to_king(&w_eval, CHANNEL2);

    // Send the shares to the king to do the final computation
    let (received_p_shares, received_q_shares, received_w_shares) = tokio::try_join!(
        received_p_shares_fut,
        received_q_shares_fut,
        received_w_shares_fut
    )?;
    // King receives shares of p, q, w
    let h_share = if let (Some(p_shares), Some(q_shares), Some(w_shares)) =
        (received_p_shares, received_q_shares, received_w_shares)
    {
        let unpack_shares = |v| {
            let mut s1 = cfg_into_iter!(transpose(v))
                .flat_map(|x| pp.unpack(x))
                .collect::<Vec<_>>();
            // swap each ith element with l*i+t element
            // TODO: Guru should help explaining this
            for i in 0..m {
                s1.swap(i, i * pp.l + pp.t);
            }
            s1
        };
        let mut p_eval = unpack_shares(p_shares);
        let mut q_eval = unpack_shares(q_shares);
        let mut w_eval = unpack_shares(w_shares);

        println!("p_eval:{}", p_eval.len());
        println!("q_eval:{}", q_eval.len());
        println!("w_eval:{}", w_eval.len());

        p_eval.truncate(m);
        q_eval.truncate(m);
        w_eval.truncate(m);

        // King do the final step of multiplication.
        let h = cfg_into_iter!(p_eval)
            .zip(q_eval)
            .zip(w_eval)
            .map(|((p, q), w)| p.mul(q).sub(w))
            .collect::<Vec<_>>();
        // pack and send to parties
        let h_shares = transpose(pack_vec(&h, pp));
        net.recv_from_king(Some(h_shares), CHANNEL0).await?
    } else {
        net.recv_from_king(None, CHANNEL0).await?
    };

    Ok(h_share)
    */
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_bn254::Fr as Bn254Fr;
    use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
    use ark_groth16::r1cs_to_qap::R1CSToQAP;
    use ark_poly::Radix2EvaluationDomain;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::cfg_iter;
    use mpc_net::LocalTestNet;

    use super::*;
    use mpc_net::MpcNet;

    #[tokio::test]
    async fn ext_witness_works() {
        let cfg = CircomConfig::<Bn254>::new(
            "../fixtures/sha256/sha256_js/sha256.wasm",
            "../fixtures/sha256/sha256.r1cs",
        )
        .unwrap();
        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("a", 1);
        builder.push_input("b", 2);
        let circom = builder.build().unwrap();
        let full_assignment = circom.witness.clone().unwrap();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        circom.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        let matrices = cs.to_matrices().unwrap();

        let num_inputs = matrices.num_instance_variables;
        let num_constraints = matrices.num_constraints;
        let expected_h =
            CircomReduction::witness_map_from_matrices::<
                Bn254Fr,
                Radix2EvaluationDomain<_>,
            >(
                &matrices, num_inputs, num_constraints, &full_assignment
            )
            .unwrap();
        let qap = crate::qap::qap::<Bn254Fr, Radix2EvaluationDomain<_>>(
            &matrices,
            &full_assignment,
        )
        .unwrap();
        let pp = PackedSharingParams::new(2);
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let qap_shares = qap.pss(&pp);
        let result = network
            .simulate_network_round(
                (pp.clone(), qap_shares),
                |net, (pp, qap_shares)| async move {
                    h(qap_shares[net.party_id() as usize].clone(), &pp, &net)
                        .await
                        .unwrap()
                },
            )
            .await;

        let computed_h = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        eprintln!("```");
        for i in 0..expected_h.len() {
            eprintln!("ACTL: {}", expected_h[i]);
            eprintln!("COMP: {}", computed_h[i]);
            if expected_h[i] == computed_h[i] {
                eprintln!("..{i}th element Matched ✅");
            } else {
                eprintln!("..{i}th element Mismatched ❌");
                // search for the element in actual_x_coeff
                let found =
                    cfg_iter!(computed_h).position(|&x| x == expected_h[i]);
                match found {
                    Some(i) => eprintln!(
                        "....However, it has been found at index: {i} ⚠️"
                    ),
                    None => eprintln!("....and Not found at all 🤔"),
                }
            }
            assert_eq!(computed_h[i], expected_h[i]);
        }
        eprintln!("```");
    }
}
