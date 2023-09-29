use ark_ec::pairing::Pairing;
use ark_ff::{FftField, PrimeField};
use dist_primitives::dmsm;
use secret_sharing::pss::PackedSharingParams;

use crate::proving_key::PackedProvingKeyShare;

#[allow(non_snake_case)]
fn compute_A<F: FftField + PrimeField + Into<u64>, E: Pairing<G1Affine = F>>(
    L: F,
    N: F,
    r: F,
    S: Vec<F>,
    a: Vec<F>,
    crs_share: PackedProvingKeyShare<E>,
    pp: PackedSharingParams<F>,
) -> E::G1Affine {
    // Calculate L * (N)^r
    let lhs = L * N.pow(&[r.into()]);

    // Start out by calculating the product of S_i^a_i
    let mut prod = F::one();
    for i in 0..S.len() {
        prod *= S[i].pow(&[a[i].into()]);
    }

    // Finally, multiply lhs by prod to find A
    lhs * prod
}

#[allow(non_snake_case)]
fn compute_B<F: FftField + PrimeField + Into<u64>, E: Pairing<G1Affine = F>>(
    Z: F,
    K: F,
    s: F,
    V: Vec<F>,
    a: Vec<F>,
) -> E::G1Affine {
    // Calculate Z * (K)^s
    let lhs = Z * K.pow(&[s.into()]);

    // Start out by calculating the product of V_i^a_i
    let mut prod = F::one();
    for i in 0..V.len() {
        prod *= V[i].pow(&[a[i].into()]);
    }

    // Finally, multiply lhs by prod to find B
    lhs * prod
}
