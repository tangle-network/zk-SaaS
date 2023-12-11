use ark_ff::{FftField, PrimeField};
use ark_poly::EvaluationDomain;
use ark_std::cfg_into_iter;
use dist_primitives::channel::MpcSerNet;
use dist_primitives::dfft::{d_fft, d_ifft};
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
    let coset_dom = domain.get_coset(F::GENERATOR).unwrap();
    let m = domain.size();

    let a_coeff_fut =
        d_ifft(qap_share.a, true, &domain, coset_dom.coset_offset(), pp, net, CHANNEL0);
    let b_coeff_fut =
        d_ifft(qap_share.b, true, &domain, coset_dom.coset_offset(), pp, net, CHANNEL1);
    let c_coeff_fut =
        d_ifft(qap_share.c, true, &domain, coset_dom.coset_offset(), pp, net, CHANNEL2);

    let (a_coeff, b_coeff, c_coeff) =
        tokio::try_join!(a_coeff_fut, b_coeff_fut, c_coeff_fut)?;

    let a_eval_fut =
        d_fft(a_coeff, true, &domain, pp, net, CHANNEL0);
    let b_eval_fut =
        d_fft(b_coeff, true, &domain, pp, net, CHANNEL1);
    let c_eval_fut =
        d_fft(c_coeff, true, &domain, pp, net, CHANNEL2);

    
    // evaluations of a, b, c over the coset
    let (a_eval, b_eval, c_eval) =
        tokio::try_join!(a_eval_fut, b_eval_fut, c_eval_fut)?;

    // compute (a.b-c)/z
    let vanishing_polynomial_over_coset = domain
            .evaluate_vanishing_polynomial(F::GENERATOR)
            .inverse()
            .unwrap();

    let h_eval = cfg_into_iter!(a_eval)
        .zip(b_eval)
        .zip(c_eval)
        .map(|((a, b), c)| (a*b - c)*vanishing_polynomial_over_coset)
        .collect::<Vec<_>>();

    // run coset_ifft to get back coefficients of h
    let h_coeff_fut =
        d_ifft(h_eval, false, &domain, coset_dom.coset_offset_inv(), pp, net, CHANNEL0);
    
    let h_coeff = tokio::try_join!(h_coeff_fut)?.0;

    Ok(h_coeff)
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_bn254::Fr as Bn254Fr;
    use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
    use ark_groth16::r1cs_to_qap::LibsnarkReduction;
    use ark_groth16::r1cs_to_qap::R1CSToQAP;
    use ark_poly::Radix2EvaluationDomain;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::cfg_iter;
    use ark_std::cfg_iter_mut;
    use dist_primitives::utils::pack::transpose;
    use mpc_net::LocalTestNet;

    use crate::qap::QAP;

    use super::*;
    use mpc_net::MpcNet;

    fn ark_h<F: PrimeField>(
        mut a: Vec<F>,
        mut b: Vec<F>,
        mut c: Vec<F>,
        domain: &Radix2EvaluationDomain<F>,
    ) -> Vec<F> {
        
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);
        domain.ifft_in_place(&mut c);

        let coset_domain = domain.get_coset(F::GENERATOR).unwrap();

        coset_domain.fft_in_place(&mut a);
        coset_domain.fft_in_place(&mut b);
        coset_domain.fft_in_place(&mut c);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        let vanishing_polynomial_over_coset = domain
            .evaluate_vanishing_polynomial(F::GENERATOR)
            .inverse()
            .unwrap();

        cfg_iter_mut!(ab).zip(c).for_each(|(ab_i, c_i)| {
            *ab_i -= &c_i;
            *ab_i *= &vanishing_polynomial_over_coset;
        });

        coset_domain.ifft_in_place(&mut ab);

        ab
    }

    #[tokio::test]
    async fn dummy_ext_witness() {
        let m = 32usize;

        let a = (0..m).map(|x| Bn254Fr::from(x as u64)).collect::<Vec<_>>();
        let b = (0..m).map(|x| Bn254Fr::from(x as u64)).collect::<Vec<_>>();
        let c = a.iter().zip(b.iter()).map(|(a, b)| a * b).collect::<Vec<_>>();

        let domain = Radix2EvaluationDomain::<Bn254Fr>::new(m).unwrap();

        let expected_h = ark_h(a.clone(), b.clone(), c.clone(), &domain);

        let pp = PackedSharingParams::<Bn254Fr>::new(2);
        let qap = QAP::<Bn254Fr, Radix2EvaluationDomain<_>> {
            num_inputs: 0,
            num_constraints: 0,
            a,
            b,
            c,
            domain,
        };
        let qap_shares = qap.pss(&pp);
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();

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
            .flat_map(|x| pp.unpack2(x))
            .collect::<Vec<_>>();

        assert_eq!(expected_h, computed_h);
    }

    #[tokio::test]
    async fn ext_witness_ark() {
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
        // let expected_h =
        //     CircomReduction::witness_map_from_matrices::<
        //         Bn254Fr,
        //         Radix2EvaluationDomain<_>,
        //     >(
        //         &matrices, num_inputs, num_constraints, &full_assignment
        //     )
        //     .unwrap();
        let ark_h = LibsnarkReduction::witness_map_from_matrices::<
        Bn254Fr,
        Radix2EvaluationDomain<_>,
        >(
            &matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        ).unwrap();

        // // collect alternate entrries from expected_h
        // let should_be_h = expected_h.iter().step_by(2).skip(1).map(|x| *x).collect::<Vec<_>>();
        // assert_eq!(should_be_h, ark_h);


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
            .flat_map(|x| pp.unpack2(x))
            .collect::<Vec<_>>();

        assert_eq!(ark_h, computed_h);

        // eprintln!("```");
        // for i in 0..expected_h.len() {
        //     eprintln!("ACTL: {}", expected_h[i]);
        //     eprintln!("COMP: {}", computed_h[i]);
        //     if expected_h[i] == computed_h[i] {
        //         eprintln!("..{i}th element Matched ✅");
        //     } else {
        //         eprintln!("..{i}th element Mismatched ❌");
        //         // search for the element in actual_x_coeff
        //         let found =
        //             cfg_iter!(computed_h).position(|&x| x == expected_h[i]);
        //         match found {
        //             Some(i) => eprintln!(
        //                 "....However, it has been found at index: {i} ⚠️"
        //             ),
        //             None => eprintln!("....and Not found at all 🤔"),
        //         }
        //     }
        //     assert_eq!(computed_h[i], expected_h[i]);
        // }
        // eprintln!("```");
    }
}
