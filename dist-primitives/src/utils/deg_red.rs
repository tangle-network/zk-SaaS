use ark_ff::FftField;
use ark_poly::domain::DomainCoeff;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use mpc_net::{MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

use crate::channel::MpcSerNet;

use super::pack::transpose;

/// Reduces the degree of a poylnomial with the help of king
pub async fn deg_red<F: FftField, T: DomainCoeff<F> + CanonicalSerialize + CanonicalDeserialize + UniformRand, Net: MpcSerNet>(
    x_share: Vec<T>,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<T>, MpcNetError> {
    let received_shares = net.send_to_king(&x_share, sid).await?;
    let king_answer: Option<Vec<Vec<T>>> =
        received_shares.map(|x_shares: Vec<Vec<T>>| {
            let mut x_shares = transpose(x_shares);
            
            for i in 0..x_shares.len() {
                let xi: Vec<T> = pp.unpack2(x_shares[i].clone());
                x_shares[i] = pp.pack(xi, &mut rand::thread_rng());
                // pp.unpack2_in_place(px_share);
                // pp.pack_from_public_in_place(px_share);
            }
            transpose(x_shares)
        });

    net.recv_from_king(king_answer, sid).await
}

#[cfg(test)]
mod tests{
    use mpc_net::{LocalTestNet, MultiplexedStreamID};
    use secret_sharing::pss::PackedSharingParams;
    use ark_bls12_377::Fr as F;
    use ark_std::UniformRand;
    use mpc_net::MpcNet;

    use crate::utils::{deg_red::deg_red, pack::transpose};

    const L: usize = 4;
    #[tokio::test]
    async fn test_deg_red() {
        let pp = PackedSharingParams::<F>::new(L);
        let rng = &mut ark_std::test_rng();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        
        let secrets: [F; L] = UniformRand::rand(rng);
        let secrets = secrets.to_vec();
        let expected: Vec<F> = secrets.iter().map(|x| (*x) * (*x)).collect();

        let shares = pp.pack(secrets, rng);
        let mul_shares: Vec<F> = shares.iter().map(|x| (*x) * (*x)).collect();
        let red_shares = network.simulate_network_round((mul_shares, pp), |net, (mul_shares, pp)| async move {
            let idx = net.party_id() as usize;
            let mul_share = mul_shares[idx].clone();

            deg_red(vec![mul_share], &pp, &net, MultiplexedStreamID::One).await.unwrap()
        }).await;
        
        let computed = transpose(red_shares)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        assert_eq!(computed, expected);
    }
}