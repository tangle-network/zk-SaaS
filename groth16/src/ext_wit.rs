use ark_ff::{FftField, PrimeField};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::SynthesisError;
use ark_std::cfg_iter_mut;
use dist_primitives::channel::MpcSerNet;
use dist_primitives::dfft::{d_fft, d_ifft};
use mpc_net::{MpcNetError, MultiplexedStreamID};
use rand::Rng;
use secret_sharing::pss::PackedSharingParams;

use crate::qap::PackedQAPShare;
use crate::ConstraintDomain;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub async fn h<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    qap_share: PackedQAPShare<F, D>,
    pp: &PackedSharingParams<F>,
    cd: &ConstraintDomain<F>,
    net: &Net,
) -> Result<Vec<F>, MpcNetError> {
    const CHANNEL0: MultiplexedStreamID = MultiplexedStreamID::Zero;
    const CHANNEL1: MultiplexedStreamID = MultiplexedStreamID::One;
    const CHANNEL2: MultiplexedStreamID = MultiplexedStreamID::Two;

    let p_coeff_fut = d_ifft(
        qap_share.a,
        true,
        2,
        false,
        &cd.constraint,
        pp,
        net,
        CHANNEL0,
    );

    let q_coeff_fut = d_ifft(
        qap_share.b,
        true,
        2,
        false,
        &cd.constraint,
        pp,
        net,
        CHANNEL1,
    );

    let (mut p_coeff, mut q_coeff) =
        tokio::try_join!(p_coeff_fut, q_coeff_fut)?;

    let root_of_unity = {
        let domain_size_double = 2 * qap_share.domain.size();
        let domain_double = D::new(domain_size_double)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        domain_double.element(1)
    };

    D::distribute_powers_and_mul_by_const(
        &mut p_coeff,
        root_of_unity,
        F::one(),
    );

    D::distribute_powers_and_mul_by_const(
        &mut q_coeff,
        root_of_unity,
        F::one(),
    );

    let p_eval_fut =
        d_fft(p_coeff, true, 1, false, &cd.constraint2, pp, net, CHANNEL0);
    let q_eval_fut =
        d_fft(q_coeff, true, 1, false, &cd.constraint2, pp, net, CHANNEL1);

    let (p_eval, q_eval) = tokio::try_join!(p_eval_fut, q_eval_fut)?;

    let mut pq = qap_share
        .domain
        .mul_polynomials_in_evaluation_domain(&p_eval, &q_eval);

    drop(p_eval);
    drop(q_eval);

    let mut w_coeff = d_ifft(
        qap_share.c,
        true,
        2,
        false,
        &cd.constraint,
        pp,
        net,
        CHANNEL2,
    )
    .await?;

    D::distribute_powers_and_mul_by_const(
        &mut w_coeff,
        root_of_unity,
        F::one(),
    );

    let w_eval =
        d_fft(w_coeff, true, 1, false, &cd.constraint2, pp, net, CHANNEL2)
            .await?;

    cfg_iter_mut!(pq)
        .zip(w_eval)
        .for_each(|(pq_i, w_i)| *pq_i -= &w_i);

    // Parties apply FFT1 locally
    let mut h_coeff =
        d_ifft(pq, false, 1, true, &cd.constraint2, pp, net, CHANNEL0).await?;

    h_coeff.truncate(qap_share.domain.size());
    Ok(h_coeff)
}

pub async fn d_ext_wit<F: FftField + PrimeField, R: Rng, Net: MpcSerNet>(
    p_eval: Vec<F>,
    q_eval: Vec<F>,
    w_eval: Vec<F>,
    rng: &mut R,
    pp: &PackedSharingParams<F>,
    cd: &ConstraintDomain<F>,
    net: &Net,
) -> Result<Vec<F>, MpcNetError> {
    // Preprocessing to account for memory usage
    let mut single_pp: Vec<Vec<F>> = vec![vec![F::one(); cd.m / pp.l]; 3];
    let mut double_pp: Vec<Vec<F>> = vec![vec![F::one(); 2 * cd.m / pp.l]; 11];
    const CHANNEL0: MultiplexedStreamID = MultiplexedStreamID::Zero;
    const CHANNEL1: MultiplexedStreamID = MultiplexedStreamID::One;
    const CHANNEL2: MultiplexedStreamID = MultiplexedStreamID::Two;
    /////////////IFFT
    // Starting with shares of evals
    let p_coeff =
        d_ifft(p_eval, true, 2, false, &cd.constraint, pp, net, CHANNEL0);
    let q_coeff =
        d_ifft(q_eval, true, 2, false, &cd.constraint, pp, net, CHANNEL1);
    let w_coeff =
        d_ifft(w_eval, true, 2, false, &cd.constraint, pp, net, CHANNEL2);

    let (p_coeff, q_coeff, w_coeff) =
        tokio::try_join!(p_coeff, q_coeff, w_coeff)?;

    // deleting randomness used
    single_pp.truncate(single_pp.len() - 3);
    double_pp.truncate(double_pp.len() - 3);

    /////////////FFT
    // Starting with shares of coefficients
    let p_eval =
        d_fft(p_coeff, true, 1, false, &cd.constraint2, pp, net, CHANNEL0);
    let q_eval =
        d_fft(q_coeff, true, 1, false, &cd.constraint2, pp, net, CHANNEL1);
    let w_eval =
        d_fft(w_coeff, true, 1, false, &cd.constraint2, pp, net, CHANNEL2);

    let (p_eval, q_eval, w_eval) = tokio::try_join!(p_eval, q_eval, w_eval)?;
    // deleting randomness used
    double_pp.truncate(double_pp.len() - 6);

    ///////////Multiply Shares
    let mut h_eval: Vec<F> = vec![F::zero(); p_eval.len()];
    for i in 0..p_eval.len() {
        h_eval[i] = p_eval[i] * q_eval[i] - w_eval[i];
    }
    drop(p_eval);
    drop(q_eval);
    drop(w_eval);

    // King drops shares of t
    let t_eval: Vec<F> = vec![F::rand(rng); h_eval.len()];
    for i in 0..h_eval.len() {
        h_eval[i] *= t_eval[i];
    }

    // Interpolate h and extract the first u_len coefficients from it as the higher coefficients will be zero
    ///////////IFFT
    // Starting with shares of evals
    let sizeinv = F::one() / F::from(cd.constraint.size);
    for i in &mut h_eval {
        *i *= sizeinv;
    }

    // Parties apply FFT1 locally
    let mut h_coeff =
        d_ifft(h_eval, false, 1, true, &cd.constraint2, pp, net, CHANNEL0)
            .await?;

    // deleting randomness used
    double_pp.truncate(double_pp.len() - 2);

    h_coeff.truncate(2 * cd.m);

    Ok(h_coeff)
}

pub async fn groth_ext_wit<F: PrimeField, R: Rng, Net: MpcSerNet>(
    rng: &mut R,
    cd: &ConstraintDomain<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
) -> Result<Vec<F>, MpcNetError> {
    let mut p_eval: Vec<F> = vec![F::rand(rng); cd.m / pp.l];
    // Shares of P, Q, W drop from the sky

    for i in 1..p_eval.len() {
        p_eval[i] = p_eval[i - 1].double();
    }
    let q_eval: Vec<F> = p_eval.clone();
    let w_eval: Vec<F> = p_eval.clone();

    d_ext_wit(p_eval, q_eval, w_eval, rng, pp, cd, net).await
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_bn254::Fr as Bn254Fr;
    use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
    use ark_groth16::r1cs_to_qap::R1CSToQAP;
    use ark_poly::EvaluationDomain;
    use ark_poly::Radix2EvaluationDomain;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;
    use mpc_net::LocalTestNet;

    use super::*;
    use mpc_net::MpcNet;

    #[tokio::test]
    async fn ext_witness_works() {
        env_logger::builder()
            .is_test(true)
            .format_timestamp(None)
            .init();
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
        let domain_size = qap.domain.size();
        let cd = ConstraintDomain::new(domain_size);
        let qap_shares = qap.pss(&pp);
        let result = network
            .simulate_network_round(
                (pp.clone(), qap_shares, cd),
                |net, (pp, qap_shares, cd)| async move {
                    h(
                        qap_shares[net.party_id() as usize].clone(),
                        &pp,
                        &cd,
                        &net,
                    )
                    .await
                },
            )
            .await;

        let h = result[0].clone().unwrap();
        for i in 0..5 {
            eprintln!("h[{i}]: {}", h[i]);
            eprintln!("expected_h[{i}]: {}", expected_h[i]);
            eprintln!("----------------------------------");
        }
        assert_eq!(h.len(), expected_h.len());
        assert_eq!(&h[0..5], &expected_h[0..5]);
    }
}
