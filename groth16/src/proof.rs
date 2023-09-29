#![allow(non_snake_case)]

use std::ops::{AddAssign, Mul};
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, PrimeField};
use ark_groth16::Proof;

fn calculate_A<
    F: FftField + PrimeField + Into<u64>,
    E: Pairing<G1Affine = F>,
>(
    L: F,
    N: F,
    r: F,
    S: Vec<F>,
    a: Vec<F>,
) -> E::G1Affine {
    // Start out by calculating the product of S_i^a_i
    let mut prod = F::one();
    for i in 0..S.len() {
        prod *= S[i].pow(&[a[i].into()]);
    }

    // Calculate L * (N)^r
    let lhs = L * N.pow(&[r.into()]);

    // Finally, multiply lhs by prod to find A
    lhs * prod
}

fn calculate_B<
    F1: FftField + PrimeField + Into<u64>,
    F2: FftField + PrimeField + Into<u64>,
    E: Pairing<G2Affine = F2>,
>(
    Z: F2,
    K: F2,
    s: F2,
    V: Vec<F2>,
    a: Vec<F1>,
) -> E::G2Affine {
    // Start out by calculating the product of V_i^a_i
    let mut prod = F2::one();
    for i in 0..V.len() {
        prod *= V[i].pow(&[a[i].into()]);
    }

    // Calculate Z * (K)^s
    let lhs = Z * K.pow(&[s.into()]);

    // Finally, multiply lhs by prod to find B
    lhs * prod
}

fn calculate_h_of_x<
    F1: FftField + PrimeField + Mul<F2> + AddAssign<<F1 as Mul<F2>>::Output>,
    F2: FftField + PrimeField,
>(
    a: Vec<F1>,
    u_x: Vec<F1>,
    v_x: Vec<F2>,
    w_x: Vec<F1>,
    t_of_x_secret_shares: Vec<F1>,
) -> Vec<F1> {
    // Calculate the sum of a*u_x
    let mut sum_u = F1::zero();
    for i in 0..a.len() {
        sum_u += a[i] * u_x[i];
    }

    // Calculate the sum of a*v_x
    let mut sum_v = F1::zero();
    for i in 0..a.len() {
        sum_v += a[i] * v_x[i];
    }

    // Calculate the sum of a*w_x
    let mut sum_w = F1::zero();
    for i in 0..a.len() {
        sum_w += a[i] * w_x[i];
    }

    // Calculate sum_u * sum_v - sum_w
    let lhs = (sum_u * sum_v) - sum_w;

    // We now have lhs = h(X)t(X)
    // Therefore h(X) = lhs / t(X)
    let mut h_x = Vec::new();
    for i in 0..t_of_x_secret_shares.len() {
        h_x.push(lhs / t_of_x_secret_shares[i]);
    }
    h_x
}

fn calculate_C<
    F1: FftField + PrimeField + Into<u64>,
    F2: FftField + PrimeField + Into<u64>,
    E: Pairing<G1Affine = F1>,
>(
    W: Vec<F1>,
    a: Vec<F1>,
    U: Vec<F1>,
    h: Vec<F1>,
    A: F1,
    s: F2,
    M: F1,
    r: F1,
    H: Vec<F1>,
) -> E::G1Affine {
    // Calculate the product of W_i^a_i
    let mut prod = F1::one();
    for i in 0..W.len() {
        prod *= W[i].pow(&[a[i].into()]);
    }

    // Calculate the product of U_i^h_i
    let mut prod2 = F1::one();
    for i in 0..U.len() {
        prod2 *= U[i].pow(&[h[i].into()]);
    }

    // Calculate the product of H_i^a_i
    let mut prod3 = F1::one();
    for i in 0..H.len() {
        prod3 *= H[i].pow(&[a[i].into()]);
    }

    // Calculate prod3^r
    let prod3r = prod3.pow(&[r.into()]);

    // Calculate prod*prod2
    let lhs = prod * prod2;

    // Calculate lhs * prod3r
    let lhs_prod3r = lhs * prod3r;

    // Calculate M^r
    let Mr = M.pow(&[r.into()]);

    // Calculate A^s
    let As = A.pow(&[s.into()]);

    // Calculate Mr * As * lhs_prod3r
    Mr * As * lhs_prod3r
}

fn calculate_groth16_proof<
    F1: FftField + PrimeField + Into<u64> + Mul<F2> + AddAssign<<F1 as Mul<F2>>::Output>,
    F2: FftField + PrimeField + Into<u64>,
    E: Pairing<G1Affine = F1, G2Affine = F2>,
>(
    L: F1,
    N: F1,
    r: F1,
    S: Vec<F1>,
    a: Vec<F1>,
    Z: F2,
    K: F2,
    s: F2,
    V: Vec<F2>,
    W: Vec<F1>,
    U: Vec<F1>,
    h: Vec<F1>,
    A: F1,
    M: F1,
    t_of_x_secret_shares: Vec<F1>,
) -> Proof<E> {
    let a_proof = calculate_A::<F1, E>(L, N, r, S, a.clone());
    let b_proof = calculate_B::<F1, F2, E>(Z, K, s, V.clone(), a.clone());

    let h_of_x_values = calculate_h_of_x(
        a.clone(),
        U.clone(),
        V,
        W.clone(),
        t_of_x_secret_shares,
    );

    let c_proof = calculate_C::<F1, F2, E>(W, a, U, h, A, s, M, r, h_of_x_values);

    Proof::<E> {
        a: a_proof,
        b: b_proof,
        c: c_proof,
    }
}
