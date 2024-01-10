mod tests {
    use ark_bls12_377::Fr as F;
    use ark_ff::FftField;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ark_std::{One, UniformRand};
    use mpc_net::LocalTestNet;
    use mpc_net::MpcNet;
    use mpc_net::MultiplexedStreamID;
    use secret_sharing::pss::PackedSharingParams;

    use crate::dfft::FftMask;
    use crate::dfft::d_fft;
    use crate::dfft::d_ifft;
    use crate::dfft::fft_in_place_rearrange;
    use crate::utils::pack::transpose;

    const L: usize = 2;
    const M: usize = L * 4;

    #[tokio::test]
    async fn d_ifft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut poly_evals = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let poly_coeffs = constraint.ifft(&poly_evals);

        fft_in_place_rearrange(&mut poly_evals);
        let mut pack_evals: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            let secrets = poly_evals
                .iter()
                .skip(i)
                .step_by(M / pp.l)
                .cloned()
                .collect::<Vec<_>>();
            pack_evals.push(pp.pack(secrets, rng));
        }

        let ifft_mask = FftMask::<F>::sample(
            false,
            F::one(),
            constraint.group_gen_inv(),
            M,
            &pp,
            rng,
        );

        let result = network
            .simulate_network_round(
                (pack_evals, ifft_mask, pp, constraint),
                |net, (pack_evals, ifft_mask, pp, constraint)| async move {
                    let idx = net.party_id() as usize;
                    let pack_eval =
                        pack_evals.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    d_ifft(
                        pack_eval,
                        &ifft_mask[idx],
                        false,
                        &constraint,
                        F::one(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let computed_poly_coeffs = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        assert_eq!(poly_coeffs, computed_poly_coeffs);
    }

    #[tokio::test]
    async fn d_fft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut poly_coeffs = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let poly_evals = constraint.fft(&poly_coeffs);

        fft_in_place_rearrange(&mut poly_coeffs);

        let mut pack_coeffs: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            let secrets = poly_coeffs
                .iter()
                .skip(i)
                .step_by(M / pp.l)
                .cloned()
                .collect::<Vec<_>>();
            pack_coeffs.push(pp.pack(secrets, rng));
        }

        let fft_mask = FftMask::<F>::sample(
            false,
            F::one(),
            constraint.group_gen(),
            M,
            &pp,
            rng,
        );

        let result = network
            .simulate_network_round(
                (pack_coeffs, fft_mask, pp, constraint),
                |net, (pack_coeffs, fft_mask, pp, constraint)| async move {
                    let idx = net.party_id() as usize;
                    let pack_coeff =
                        pack_coeffs.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    d_fft(
                        pack_coeff,
                        &fft_mask[idx],
                        false,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let computed_poly_evals = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        assert_eq!(poly_evals, computed_poly_evals);
    }

    #[tokio::test]
    async fn d_ifftxd_fft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut poly_evals = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let expected_evals = poly_evals.clone();

        fft_in_place_rearrange(&mut poly_evals);
        let mut pack_evals: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            let secrets = poly_evals
                .iter()
                .skip(i)
                .step_by(M / pp.l)
                .cloned()
                .collect::<Vec<_>>();
            pack_evals.push(pp.pack(secrets, rng));
        }

        let ifft_mask = FftMask::<F>::sample(
            true,
            F::one(),
            constraint.group_gen_inv(),
            M,
            &pp,
            rng,
        );

        let fft_mask = FftMask::<F>::sample(
            false,
            F::one(),
            constraint.group_gen(),
            M,
            &pp,
            rng,
        );


        let result = network
            .simulate_network_round(
                (pack_evals, ifft_mask, fft_mask, pp, constraint),
                |net, (pack_evals, ifft_mask, fft_mask, pp, constraint)| async move {
                    let idx = net.party_id() as usize;
                    let pack_eval =
                        pack_evals.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    let p_coeff = d_ifft(
                        pack_eval,
                        &ifft_mask[idx],
                        true,
                        &constraint,
                        F::one(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    d_fft(
                        p_coeff,
                        &fft_mask[idx],
                        false,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;
        let computed_poly_evals = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        assert_eq!(expected_evals, computed_poly_evals);
    }

    #[tokio::test]
    async fn coset_d_ifftxd_fft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let constraint_coset = constraint.get_coset(F::GENERATOR).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut poly_evals = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let expected_poly_evals = poly_evals.clone();

        fft_in_place_rearrange(&mut poly_evals);
        let mut pack_evals: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            let secrets = poly_evals
                .iter()
                .skip(i)
                .step_by(M / pp.l)
                .cloned()
                .collect::<Vec<_>>();
            pack_evals.push(pp.pack(secrets, rng));
        }

        let fft_mask = [
            FftMask::<F>::sample(
                true,
                constraint_coset.coset_offset(),
                constraint.group_gen_inv(),
                M,
                &pp,
                rng,
            ),
            FftMask::<F>::sample(
                true,
                F::one(),
                constraint_coset.group_gen(),
                M,
                &pp,
                rng,
            ),
            FftMask::<F>::sample(
                true,
                constraint_coset.coset_offset_inv(),
                constraint.group_gen_inv(),
                M,
                &pp,
                rng,
            ),
            FftMask::<F>::sample(
                false,
                F::one(),
                constraint_coset.group_gen(),
                M,
                &pp,
                rng,
            ),
        ];

        eprintln!("Running coset_d_ifftxd_ifft ...");
        let result = network
            .simulate_network_round(
                (pack_evals, fft_mask, pp, constraint, constraint_coset),
                |net, (pack_evals, fft_mask, pp, constraint, constraint_coset)| async move {
                    let idx = net.party_id() as usize;
                    let peval_share =
                        pack_evals.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    // starting with evals over dom
                    let p_coeff = d_ifft(
                        peval_share,
                        &fft_mask[0][idx],
                        true,
                        &constraint,
                        constraint_coset.coset_offset(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    let coset_peval_share = d_fft(
                        p_coeff,
                        &fft_mask[1][idx],
                        true,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    // obtained evals over coset_dom
                    let p_coeff = d_ifft(
                        coset_peval_share,
                        &fft_mask[2][idx],
                        true,
                        &constraint,
                        constraint_coset.coset_offset_inv(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    d_fft(
                        p_coeff,
                        &fft_mask[3][idx],
                        false,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                    // back to evals over dom
                },
            )
            .await;
        eprintln!("coset_d_ifftxd_fft done ...");
        eprintln!("Computing x evals from the shares ...");
        let computed_poly_evals = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        assert_eq!(expected_poly_evals, computed_poly_evals);
    }
}
