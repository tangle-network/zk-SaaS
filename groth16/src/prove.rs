#![allow(non_snake_case, clippy::too_many_arguments)]

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{FftField, PrimeField};
use dist_primitives::dmsm::d_msm;
use mpc_net::{MpcNet, MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

/// A = L.(N)^r.∏{i∈[0,m]}(S_i)^a_i
pub async fn compute_A<
    E: Pairing<G1Affine = F>,
    F: FftField + PrimeField,
    Net: MpcNet,
>(
    L: E::G1,
    N: E::G1,
    r: F,
    (s_pp, S): (PackedSharingParams<E::ScalarField>, Vec<E::G1Affine>),
    a: Vec<E::ScalarField>,
    net: &mut Net,
    sid: MultiplexedStreamID,
) -> Result<E::G1Affine, MpcNetError> {
    // We use variables (L, N, (S_i){i∈[0,m]}) to denote elements in G1
    // We also assume that all the servers computing the proof
    // get L, N in the clear and only receive packed shares of the remaining elements
    // specifically, each server gets a share of (S_i)^a_i for i∈[0,Q-1].
    //
    // Given packed shares of S_i and au_i terms, the servers can use πMSM (dmsm) to compute ∏{i∈[0,Q−1]}(S_i)^a_i.
    // Since the output of MSM are regular shares, they can then be combined with L, N and regular shares
    // of r to get regular shares of A.

    // Calculate (N)^r
    let v0 = N.into_affine().pow(r.into_bigint());
    // Calculate L.(N)^r
    let v1 = L.into_affine().mul(v0);

    // Calculate ∏{i∈[0,m]}(S_i)^a_i using dmsm

    let prod = d_msm::<E::G1, _>(&S, &a, &s_pp, net, sid).await?;

    Ok(prod.into_affine().mul(v1))
}

/// B = Z.(K)^s.∏{i∈[0,m]}(V_i)^a_i
pub async fn compute_B<
    E: Pairing<G2Affine = F>,
    F: FftField + PrimeField,
    Net: MpcNet,
>(
    Z: E::G2,
    K: E::G2,
    s: F,
    (v_pp, V): (PackedSharingParams<E::ScalarField>, Vec<E::G2Affine>),
    a: Vec<E::ScalarField>,
    net: &mut Net,
    sid: MultiplexedStreamID,
) -> Result<E::G2Affine, MpcNetError> {
    // We use variables (Z, K, (V_i){i∈[0,m]}) to denote elements in G2
    // We also assume that all the servers computing the proof
    // get Z, K in the clear and only receive packed shares of the remaining elements
    // specifically, each server gets a share of (V_i)^a_i for i∈[0,Q-1].
    //
    // Given packed shares of V_i and av_i terms, the servers can use πMSM (dmsm) to compute ∏{i∈[0,Q−1]}(V_i)^a_i.
    // Since the output of MSM are regular shares, they can then be combined with Z, K and regular shares
    // of s to get regular shares of A.

    // Calculate (K)^s
    let v0 = K.into_affine().pow(s.into_bigint());
    // Calculate Z.(K)^s
    let v1 = Z.into_affine().mul(v0);
    // Calculate ∏{i∈[0,m]}(V_i)^a_i using dmsm
    let prod = d_msm::<E::G2, _>(&V, &a, &v_pp, net, sid).await?;
    Ok(prod.into_affine().mul(v1))
}

/// C = (∏{i∈[l+1,m]}(W_i)^a_i)(∏{i∈[0,Q−2]}(U_i)^h_i).A^s.M^r.(∏{i∈[0,m]}(H_i)^a_i)^r
pub async fn compute_C<
    E: Pairing<G1Affine = F>,
    F: FftField + PrimeField,
    Net: MpcNet,
>(
    A: E::G1Affine,
    M: E::G1,
    s: F,
    r: F,
    (w_pp, W): (PackedSharingParams<E::ScalarField>, Vec<E::G1Affine>),
    (u_pp, U): (PackedSharingParams<E::ScalarField>, Vec<E::G1Affine>),
    (h_pp, H): (PackedSharingParams<E::ScalarField>, Vec<E::G1Affine>),
    a: Vec<E::ScalarField>,
    h: Vec<E::ScalarField>,
    net: &mut Net,
    sid: MultiplexedStreamID,
) -> Result<E::G1Affine, MpcNetError> {
    // We use variables (A, M, ∏{i∈[l+1,m]}(W_i)^a_i, ∏{i∈[0,Q−2]}(U_i)h_i, ∏{i∈[0,m]}(H_i)^a_i)
    // to denote elements in G1. We also assume that all the servers computing the proof
    // get A, M, s, r and h in the clear and only receive packed shares of the remaining elements.

    // Calculate ∏{i∈[l+1,m]}(W_i)^a_i using dmsm
    let w = d_msm::<E::G1, _>(&W, &a, &w_pp, net, sid).await?;
    // Calculate ∏{i∈[0,Q−2]}(U_i)^h_i using dmsm
    let u = d_msm::<E::G1, _>(&U, &h, &u_pp, net, sid).await?;
    // Calculate ∏{i∈[0,m]}(H_i)^a_i using dmsm
    let h = d_msm::<E::G1, _>(&H, &a, &h_pp, net, sid).await?;

    // Calculate A^s
    let v0 = A.pow(s.into_bigint());
    // Calculate M^r
    let v1 = M.into_affine().pow(r.into_bigint());
    // Calculate (∏{i∈[0,m]}(H_i)^a_i)^r
    let v2 = h.into_affine().pow(r.into_bigint());
    // finally compute C
    let c = w.into_affine().mul(u.into_affine()).mul(v0).mul(v1).mul(v2);
    Ok(c)
}
