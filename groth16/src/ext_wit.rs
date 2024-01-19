use crate::qap::PackedQAPShare;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::cfg_into_iter;
use dist_primitives::dfft::{d_fft, d_ifft, FftMask};
use dist_primitives::utils::deg_red::{deg_red, DegRedMask};
use mpc_net::ser_net::MpcSerNet;
use mpc_net::{MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub async fn libsnark_h<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    qap_share: PackedQAPShare<F, D>,
    fft_mask: &[FftMask<F>; 7], // 3 ifft, 3 fft and 1 coset ifft
    pp: &PackedSharingParams<F>,
    net: &Net,
) -> Result<Vec<F>, MpcNetError> {
    const CHANNEL0: MultiplexedStreamID = MultiplexedStreamID::Zero;
    const CHANNEL1: MultiplexedStreamID = MultiplexedStreamID::One;
    const CHANNEL2: MultiplexedStreamID = MultiplexedStreamID::Two;

    let domain = qap_share.domain;
    let coset_dom = domain.get_coset(F::GENERATOR).unwrap();

    let a_coeff_fut = d_ifft(
        qap_share.a,
        &fft_mask[0],
        true,
        &domain,
        coset_dom.coset_offset(),
        pp,
        net,
        CHANNEL0,
    );
    let b_coeff_fut = d_ifft(
        qap_share.b,
        &fft_mask[1],
        true,
        &domain,
        coset_dom.coset_offset(),
        pp,
        net,
        CHANNEL1,
    );
    let c_coeff_fut = d_ifft(
        qap_share.c,
        &fft_mask[2],
        true,
        &domain,
        coset_dom.coset_offset(),
        pp,
        net,
        CHANNEL2,
    );

    let (a_coeff, b_coeff, c_coeff) =
        tokio::try_join!(a_coeff_fut, b_coeff_fut, c_coeff_fut)?;

    let a_eval_fut =
        d_fft(a_coeff, &fft_mask[3], true, &domain, pp, net, CHANNEL0);
    let b_eval_fut =
        d_fft(b_coeff, &fft_mask[4], true, &domain, pp, net, CHANNEL1);
    let c_eval_fut =
        d_fft(c_coeff, &fft_mask[5], true, &domain, pp, net, CHANNEL2);

    // evaluations of a, b, c over the coset
    let (a_eval, b_eval, c_eval) =
        tokio::try_join!(a_eval_fut, b_eval_fut, c_eval_fut)?;

    // compute (ab-c)/z
    let vanishing_polynomial_over_coset = domain
        .evaluate_vanishing_polynomial(F::GENERATOR)
        .inverse()
        .unwrap();

    let h_eval = cfg_into_iter!(a_eval)
        .zip(b_eval)
        .zip(c_eval)
        .map(|((a, b), c)| (a * b - c) * vanishing_polynomial_over_coset)
        .collect::<Vec<_>>();

    // run coset_ifft to get back coefficients of h
    let h_coeff = d_ifft(
        h_eval,
        &fft_mask[6],
        false,
        &domain,
        coset_dom.coset_offset_inv(),
        pp,
        net,
        CHANNEL0,
    )
    .await?;

    Ok(h_coeff)
}

pub async fn circom_h<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    qap_share: PackedQAPShare<F, D>,
    fft_mask: &[FftMask<F>; 6], // 3 ifft and 3 fft
    degred_mask: &DegRedMask<F, F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
) -> Result<Vec<F>, MpcNetError> {
    const CHANNEL0: MultiplexedStreamID = MultiplexedStreamID::Zero;
    const CHANNEL1: MultiplexedStreamID = MultiplexedStreamID::One;
    const CHANNEL2: MultiplexedStreamID = MultiplexedStreamID::Two;

    let domain = qap_share.domain;
    let root_of_unity = {
        let domain_size_double = 2 * domain.size();
        let domain_double =
            Radix2EvaluationDomain::<F>::new(domain_size_double).unwrap();
        domain_double.element(1)
    };

    let a_coeff_fut = d_ifft(
        qap_share.a,
        &fft_mask[0],
        true,
        &domain,
        root_of_unity,
        pp,
        net,
        CHANNEL0,
    );
    let b_coeff_fut = d_ifft(
        qap_share.b,
        &fft_mask[1],
        true,
        &domain,
        root_of_unity,
        pp,
        net,
        CHANNEL1,
    );
    let c_coeff_fut = d_ifft(
        qap_share.c,
        &fft_mask[2],
        true,
        &domain,
        root_of_unity,
        pp,
        net,
        CHANNEL2,
    );

    let (a_coeff, b_coeff, c_coeff) =
        tokio::try_join!(a_coeff_fut, b_coeff_fut, c_coeff_fut)?;

    let a_eval_fut =
        d_fft(a_coeff, &fft_mask[3], false, &domain, pp, net, CHANNEL0);
    let b_eval_fut =
        d_fft(b_coeff, &fft_mask[4], false, &domain, pp, net, CHANNEL1);
    let c_eval_fut =
        d_fft(c_coeff, &fft_mask[5], false, &domain, pp, net, CHANNEL2);

    // evaluations of a, b, c over the coset
    let (a_eval, b_eval, c_eval) =
        tokio::try_join!(a_eval_fut, b_eval_fut, c_eval_fut)?;

    // compute (ab-c)
    let h_eval = cfg_into_iter!(a_eval)
        .zip(b_eval)
        .zip(c_eval)
        .map(|((a, b), c)| (a * b - c))
        .collect::<Vec<_>>();

    let h_eval_red = deg_red(h_eval, degred_mask, pp, net, CHANNEL0).await?;
    Ok(h_eval_red)
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
    use ark_std::cfg_iter_mut;
    use ark_std::One;
    use dist_primitives::utils::deg_red::DegRedMask;
    use dist_primitives::utils::pack::transpose;
    use mpc_net::LocalTestNet;
    use rand::thread_rng;

    use crate::qap::QAP;

    use super::*;
    use mpc_net::MpcNet;

    fn libsnark_ref<F: PrimeField>(
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

    fn circom_ref<F: PrimeField>(
        mut a: Vec<F>,
        mut b: Vec<F>,
        mut c: Vec<F>,
        domain: &Radix2EvaluationDomain<F>,
    ) -> Vec<F> {
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let root_of_unity = {
            let domain_size_double = 2 * domain.size();
            let domain_double =
                Radix2EvaluationDomain::<F>::new(domain_size_double).unwrap();
            domain_double.element(1)
        };
        Radix2EvaluationDomain::<F>::distribute_powers_and_mul_by_const(
            &mut a,
            root_of_unity,
            F::one(),
        );
        Radix2EvaluationDomain::<F>::distribute_powers_and_mul_by_const(
            &mut b,
            root_of_unity,
            F::one(),
        );

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        Radix2EvaluationDomain::<F>::distribute_powers_and_mul_by_const(
            &mut c,
            root_of_unity,
            F::one(),
        );
        domain.fft_in_place(&mut c);

        cfg_iter_mut!(ab)
            .zip(c)
            .for_each(|(ab_i, c_i)| *ab_i -= &c_i);

        ab
    }

    #[tokio::test]
    async fn libsnark_dummy_ext_witness() {
        let m = 32usize;

        let rng = &mut thread_rng();
        let a = (0..m).map(|x| Bn254Fr::from(x as u64)).collect::<Vec<_>>();
        let b = (0..m).map(|x| Bn254Fr::from(x as u64)).collect::<Vec<_>>();
        let c = a
            .iter()
            .zip(b.iter())
            .map(|(a, b)| a * b)
            .collect::<Vec<_>>();

        let domain = Radix2EvaluationDomain::<Bn254Fr>::new(m).unwrap();

        let expected_h = libsnark_ref(a.clone(), b.clone(), c.clone(), &domain);

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

        let coset_dom = domain.get_coset(Bn254Fr::GENERATOR).unwrap();
        let fft_masks = [
            FftMask::<Bn254Fr>::sample(
                true,
                coset_dom.coset_offset(),
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                coset_dom.coset_offset(),
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                coset_dom.coset_offset(),
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                false,
                coset_dom.coset_offset_inv(),
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
        ];

        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();

        let result = network
            .simulate_network_round(
                (pp.clone(), qap_shares, fft_masks),
                |net, (pp, qap_shares, fft_masks)| async move {
                    let fft_mask = [
                        fft_masks[0][net.party_id() as usize].clone(),
                        fft_masks[1][net.party_id() as usize].clone(),
                        fft_masks[2][net.party_id() as usize].clone(),
                        fft_masks[3][net.party_id() as usize].clone(),
                        fft_masks[4][net.party_id() as usize].clone(),
                        fft_masks[5][net.party_id() as usize].clone(),
                        fft_masks[6][net.party_id() as usize].clone(),
                    ];

                    libsnark_h(
                        qap_shares[net.party_id() as usize].clone(),
                        &fft_mask,
                        &pp,
                        &net,
                    )
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
    async fn circom_dummy_ext_witness() {
        let m = 1 << 10;

        let a = (0..m).map(|x| Bn254Fr::from(x as u64)).collect::<Vec<_>>();
        let b = (0..m).map(|x| Bn254Fr::from(x as u64)).collect::<Vec<_>>();
        let c = a
            .iter()
            .zip(b.iter())
            .map(|(a, b)| a * b)
            .collect::<Vec<_>>();

        let domain = Radix2EvaluationDomain::<Bn254Fr>::new(m).unwrap();

        let expected_h = circom_ref(a.clone(), b.clone(), c.clone(), &domain);

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
        let rng = &mut thread_rng();

        let root_of_unity = {
            let domain_size_double = 2 * domain.size();
            let domain_double =
                Radix2EvaluationDomain::<Bn254Fr>::new(domain_size_double)
                    .unwrap();
            domain_double.element(1)
        };

        let fft_masks = [
            FftMask::<Bn254Fr>::sample(
                true,
                root_of_unity,
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                root_of_unity,
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                root_of_unity,
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                false,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                false,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                false,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
        ];

        let degred_masks = DegRedMask::<Bn254Fr, Bn254Fr>::sample(
            &pp,
            Bn254Fr::from(1u32),
            domain.size() / pp.l,
            rng,
        );

        let result = network
            .simulate_network_round(
                (pp.clone(), qap_shares, fft_masks, degred_masks),
                |net, (pp, qap_shares, fft_masks, degred_masks)| async move {
                    let fft_mask = [
                        fft_masks[0][net.party_id() as usize].clone(),
                        fft_masks[1][net.party_id() as usize].clone(),
                        fft_masks[2][net.party_id() as usize].clone(),
                        fft_masks[3][net.party_id() as usize].clone(),
                        fft_masks[4][net.party_id() as usize].clone(),
                        fft_masks[5][net.party_id() as usize].clone(),
                    ];

                    circom_h(
                        qap_shares[net.party_id() as usize].clone(),
                        &fft_mask,
                        &degred_masks[net.party_id() as usize],
                        &pp,
                        &net,
                    )
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
    async fn ext_witness_circom() {
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
        let h = CircomReduction::witness_map_from_matrices::<
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

        let domain = qap_shares[0].domain;
        let rng = &mut thread_rng();

        let root_of_unity = {
            let domain_size_double = 2 * domain.size();
            let domain_double =
                Radix2EvaluationDomain::<Bn254Fr>::new(domain_size_double)
                    .unwrap();
            domain_double.element(1)
        };

        let fft_masks = [
            FftMask::<Bn254Fr>::sample(
                true,
                root_of_unity,
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                root_of_unity,
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                true,
                root_of_unity,
                domain.group_gen_inv(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                false,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                false,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
            FftMask::<Bn254Fr>::sample(
                false,
                Bn254Fr::one(),
                domain.group_gen(),
                domain.size(),
                &pp,
                rng,
            ),
        ];

        let degred_masks = DegRedMask::<Bn254Fr, Bn254Fr>::sample(
            &pp,
            Bn254Fr::from(1u32),
            domain.size() / pp.l,
            rng,
        );

        let result = network
            .simulate_network_round(
                (pp.clone(), qap_shares, fft_masks, degred_masks),
                |net, (pp, qap_shares, fft_masks, degred_masks)| async move {
                    let fft_mask = [
                        fft_masks[0][net.party_id() as usize].clone(),
                        fft_masks[1][net.party_id() as usize].clone(),
                        fft_masks[2][net.party_id() as usize].clone(),
                        fft_masks[3][net.party_id() as usize].clone(),
                        fft_masks[4][net.party_id() as usize].clone(),
                        fft_masks[5][net.party_id() as usize].clone(),
                    ];

                    circom_h(
                        qap_shares[net.party_id() as usize].clone(),
                        &fft_mask,
                        &degred_masks[net.party_id() as usize],
                        &pp,
                        &net,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let computed_h = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        assert_eq!(h, computed_h);
    }
}
