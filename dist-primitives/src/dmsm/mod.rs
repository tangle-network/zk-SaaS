use crate::channel::MpcSerNet;
use ark_ec::{CurveGroup, Group};
use ark_poly::EvaluationDomain;
use mpc_net::{MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

pub fn unpackexp<G: Group, Net: MpcSerNet>(
    mut shares: Vec<G>,
    degree2: bool,
    pp: &PackedSharingParams<G::ScalarField>,
    _net: &Net,
) -> Vec<G> {
    // interpolate shares
    pp.share.ifft_in_place(&mut shares);

    // Simplified this assertion using a zero check in the last n - d - 1 entries

    #[cfg(debug_assertions)]
    {
        let n = _net.n_parties();
        let d: usize = if degree2 {
            2 * (pp.t + pp.l)
        } else {
            pp.t + pp.l
        };

        for share in shares.iter().take(n).skip(d + 1) {
            debug_assert!(
                share.is_zero(),
                "Polynomial has degree > degree bound {})",
                d
            );
        }
    }

    // Evaluate the polynomial on the coset to recover secrets
    if degree2 {
        pp.secret2.fft_in_place(&mut shares);
        shares[0..pp.l * 2]
            .iter()
            .step_by(2)
            .copied()
            .collect::<Vec<_>>()
    } else {
        pp.secret.fft_in_place(&mut shares);
        shares[0..pp.l].to_vec()
    }
}

pub fn packexp_from_public<G: Group>(
    secrets: &[G],
    pp: &PackedSharingParams<G::ScalarField>,
) -> Vec<G> {
    let mut result = secrets.to_vec();
    // interpolate secrets
    pp.secret.ifft_in_place(&mut result);

    // evaluate polynomial to get shares
    pp.share.fft_in_place(&mut result);

    result
}

pub async fn d_msm<G: CurveGroup, Net: MpcSerNet>(
    bases: &[G::Affine],
    scalars: &[G::ScalarField],
    pp: &PackedSharingParams<G::ScalarField>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<G, MpcNetError> {
    // Using affine is important because we don't want to create an extra vector for converting Projective to Affine.
    // Eventually we do have to convert to Projective but this will be pp.l group elements instead of m()

    // First round of local computation done by parties
    println!("bases: {}, scalars: {}", bases.len(), scalars.len());
    let c_share = G::msm(bases, scalars).unwrap();
    // Now we do degree reduction -- psstoss
    // Send to king who reduces and sends shamir shares (not packed).
    // Should be randomized. First convert to projective share.

    let n_parties = net.n_parties();
    let king_answer: Option<Vec<G>> = net
        .send_to_king(&c_share, sid)
        .await?
        .map(|shares: Vec<G>| {
            let output: G = unpackexp(shares, true, pp, &net).iter().sum();
            vec![output; n_parties]
        });

    net.recv_from_king(king_answer, sid).await
}

#[cfg(test)]
mod tests {
    use ark_ec::bls12::Bls12Config;
    use ark_ec::CurveGroup;
    use ark_ec::Group;
    use ark_ec::VariableBaseMSM;
    use ark_std::UniformRand;
    use ark_std::Zero;
    use secret_sharing::pss::PackedSharingParams;

    use ark_bls12_377::G1Affine;
    use ark_bls12_377::G1Projective as G1P;
    use mpc_net::LocalTestNet;

    type F = <ark_ec::short_weierstrass::Projective<
        <ark_bls12_377::Config as Bls12Config>::G1Config,
    > as Group>::ScalarField;

    use crate::dmsm::packexp_from_public;
    use crate::dmsm::unpackexp;
    use crate::utils::pack::transpose;

    const L: usize = 2;
    const N: usize = L * 4;
    // const T:usize = N/2 - L - 1;
    const M: usize = 1 << 8;

    #[tokio::test]
    async fn pack_unpack_test() {
        println!("pack_unpack_test");
        let net = LocalTestNet::new_local_testnet(4).await.unwrap();

        println!("net init done");

        net.simulate_network_round(|mut net| async move {
            let pp = PackedSharingParams::<F>::new(L);
            let rng = &mut ark_std::test_rng();
            let secrets: [G1P; L] = UniformRand::rand(rng);
            let secrets = secrets.to_vec();

            let shares = packexp_from_public(&secrets, &pp);
            let result = unpackexp(shares, false, &pp, &mut net);
            assert_eq!(secrets, result);
        })
        .await;
    }

    #[tokio::test]
    async fn pack_unpack2_test() {
        let net = LocalTestNet::new_local_testnet(4).await.unwrap();

        net.simulate_network_round(|mut net| async move {
            let pp = PackedSharingParams::<F>::new(L);
            let rng = &mut ark_std::test_rng();

            let gsecrets: [G1P; M] = [G1P::rand(rng); M];
            let gsecrets = gsecrets.to_vec();

            let fsecrets: [F; M] = [F::from(1_u32); M];
            let fsecrets = fsecrets.to_vec();

            ///////////////////////////////////////
            let gsecrets_aff: Vec<G1Affine> =
                gsecrets.iter().map(|s| (*s).into()).collect();
            let expected = G1P::msm(&gsecrets_aff, &fsecrets).unwrap();
            ///////////////////////////////////////
            let gshares: Vec<Vec<G1P>> = gsecrets
                .chunks(L)
                .map(|s| packexp_from_public(s, &pp))
                .collect();

            let fshares: Vec<Vec<F>> = fsecrets
                .chunks(L)
                .map(|s| pp.pack_from_public(s.to_vec()))
                .collect();

            let gshares = transpose(gshares);
            let fshares = transpose(fshares);

            let mut result = vec![G1P::zero(); N];

            for i in 0..N {
                let temp_aff: Vec<
                    <ark_ec::short_weierstrass::Projective<
                        <ark_bls12_377::Config as Bls12Config>::G1Config,
                    > as CurveGroup>::Affine,
                > = gshares[i].iter().map(|s| (*s).into()).collect();
                result[i] = G1P::msm(&temp_aff, &fshares[i]).unwrap();
            }
            let result: G1P =
                unpackexp(result, true, &pp, &mut net).iter().sum();
            assert_eq!(expected, result);
        })
        .await;
    }
}
