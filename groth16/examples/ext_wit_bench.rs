use ark_bls12_377::Fr;
use ark_ff::PrimeField;
use groth16::{ext_wit::d_ext_wit, ConstraintDomain};
use mpc_net::{LocalTestNet as Net, MpcNet};
use rand::Rng;
use secret_sharing::pss::PackedSharingParams;

async fn groth_ext_wit<F: PrimeField, R: Rng, Net: MpcNet>(
    rng: &mut R,
    cd: &ConstraintDomain<F>,
    pp: &PackedSharingParams<F>,
    net: &Net,
) -> Vec<F> {
    let mut p_eval: Vec<F> = vec![F::rand(rng); cd.m / pp.l];
    // Shares of P, Q, W drop from the sky
    // P = Σ a_i . u_i
    // Q = Σ a_i ⋅ v_i
    // W = Σ a_i ⋅ w_i

    for i in 1..p_eval.len() {
        p_eval[i] = p_eval[i - 1].double();
    }
    let q_eval: Vec<F> = p_eval.clone();
    let w_eval: Vec<F> = p_eval.clone();

    d_ext_wit(p_eval, q_eval, w_eval, rng, pp, cd, net)
        .await
        .unwrap()
}

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp(None).init();

    let network = Net::new_local_testnet(4).await.unwrap();

    network
        .simulate_network_round((), |net, _| async move {
            let rng = &mut ark_std::test_rng();
            let pp = PackedSharingParams::<Fr>::new(2);
            let cd = ConstraintDomain::<Fr>::new(1 << 14);
            groth_ext_wit(rng, &cd, &pp, &net).await;
        })
        .await;
}
