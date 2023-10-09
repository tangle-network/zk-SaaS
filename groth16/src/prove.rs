#![allow(non_snake_case)]

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{FftField, PrimeField};
use dist_primitives::dmsm::d_msm;
use secret_sharing::pss::PackedSharingParams;

/// A = L.(N)^r.∏{i∈[0,m]}(S_i)^a_i
pub fn compute_A<E: Pairing<G1Affine = F>, F: FftField + PrimeField>(
    L: E::G1,
    N: E::G1,
    r: F,
    s_pp: PackedSharingParams<E::ScalarField>,
    S: Vec<E::G1Affine>,
    a: Vec<E::ScalarField>,
) -> E::G1Affine {
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

    let prod = d_msm::<E::G1>(&S, &a, &s_pp);

    prod.into_affine().mul(v1)
}

/// B = Z.(K)^s.∏{i∈[0,m]}(V_i)^a_i
pub fn compute_B<E: Pairing<G2Affine = F>, F: FftField + PrimeField>(
    Z: E::G2,
    K: E::G2,
    s: F,
    v_pp: PackedSharingParams<E::ScalarField>,
    V: Vec<E::G2Affine>,
    a: Vec<E::ScalarField>,
) -> E::G2Affine {
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
    let prod = d_msm::<E::G2>(&V, &a, &v_pp);
    prod.into_affine().mul(v1)
}
