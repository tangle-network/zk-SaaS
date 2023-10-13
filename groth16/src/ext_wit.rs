use ark_ff::{FftField, PrimeField};
use dist_primitives::channel::MpcSerNet;
use dist_primitives::dfft::{d_fft, d_ifft};
use mpc_net::{MpcNetError, MultiplexedStreamID};
use rand::Rng;
use secret_sharing::pss::PackedSharingParams;

use crate::ConstraintDomain;

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
