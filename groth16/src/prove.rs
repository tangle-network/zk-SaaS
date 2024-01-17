#![allow(non_snake_case, clippy::too_many_arguments)]

use ark_ec::pairing::Pairing;
use ark_std::Zero;
use dist_primitives::dmsm::{d_msm, MsmMask};
use mpc_net::{MpcNet, MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;

/// A = L.(N)^r.∏{i∈[0,m]}(S_i)^a_i
#[derive(Debug, Clone, Copy)]
pub struct A<'a, E: Pairing> {
    /// L is `a_query[0]`
    pub L: E::G1Affine,
    /// N is `delta_g1`
    pub N: E::G1Affine,
    /// AG1 is `alpha_g1`
    pub AG1: E::G1Affine,
    /// S is `a_query[1..]`
    pub S: &'a [E::G1Affine],
    /// a is `assignment`
    pub a: &'a [E::ScalarField],
    pub r: E::ScalarField,
    pub pp: &'a PackedSharingParams<E::ScalarField>,
}

impl<'a, E: Pairing> A<'a, E> {
    /// Computes A
    pub async fn compute<Net: MpcNet>(
        self,
        msm_mask: &MsmMask<E::G1>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<E::G1, MpcNetError> {
        // We use variables (L, N, AG1, (S_i){i∈[0,m]}) to denote elements in G1
        // We also assume that all the servers computing the proof
        // get L, N, AG1, in the clear and only receive packed shares of the remaining elements
        // specifically, each server gets a share of (S_i)^a_i for i∈[0,Q-1].
        //
        // Given packed shares of S_i and au_i terms, the servers can use πMSM (dmsm) to compute ∏{i∈[0,Q−1]}(S_i)^a_i.
        // Since the output of MSM are regular shares, they can then be combined with L, N and regular shares
        // of r to get regular shares of A.
        // Note: for simplicity, we actually implement MSM such that the output shares are packed shares of the same
        // value repeated l times. Therefore they can be combined with L, N and packed shares of r to get packed shares of A.

        // Calculate (N)^r
        let v0 = self.N * self.r;
        // Calculate L.(N)^r
        let v1 = self.L + v0;

        // Calculate ∏{i∈[0,m]}(S_i)^a_i using dmsm
        let prod =
            d_msm::<E::G1, _>(self.S, self.a, msm_mask, self.pp, net, sid)
                .await?;

        let A = (v1 + prod) + self.AG1;

        Ok(A)
    }
}

/// B (in G1) = Z.(K)^s.∏{i∈[0,m]}(H_i)^a_i
#[derive(Debug, Clone, Copy)]
pub struct BInG1<'a, E: Pairing> {
    /// Z is `b_g1_query[0]`
    pub Z: E::G1Affine,
    /// K is `delta_g1`
    pub K: E::G1Affine,
    /// BG1 is `beta_g1`
    pub BG1: E::G1Affine,
    /// H is `b_g1_query[1..]`
    pub H: &'a [E::G1Affine],
    /// a is `assignment`
    pub a: &'a [E::ScalarField],
    pub s: E::ScalarField,
    pub r: E::ScalarField,
    pub pp: &'a PackedSharingParams<E::ScalarField>,
}

impl<'a, E: Pairing> BInG1<'a, E> {
    /// Computes B in G1
    pub async fn compute<Net: MpcNet>(
        self,
        msm_mask: &MsmMask<E::G1>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<E::G1, MpcNetError> {
        // We use variables (Z, K, BG1, (H_i){i∈[0,m]}) to denote elements in G1
        // We also assume that all the servers computing the proof
        // get Z, K, BG1 in the clear and only receive packed shares of the remaining elements
        // specifically, each server gets a share of (H_i)^a_i for i∈[0,Q-1].
        //
        // Given packed shares of H_i and ah_i terms, the servers can use πMSM (dmsm) to compute ∏{i∈[0,Q−1]}(H_i)^a_i.
        // Since the output of MSM are regular shares, they can then be combined with Z, K, BG1 and regular shares
        // of s to get regular shares of B in G1.

        if self.r.is_zero() {
            return Ok(E::G1::zero());
        }

        // Calculate (K)^s
        let v0 = self.K * self.s;
        // Calculate Z.(K)^s
        let v1 = self.Z + v0;
        // Calculate ∏{i∈[0,m]}(H_i)^a_i using dmsm
        let prod =
            d_msm::<E::G1, _>(self.H, self.a, msm_mask, self.pp, net, sid)
                .await?;

        let B = (v1 + prod) + self.BG1;

        Ok(B)
    }
}

/// B (in G2) = Z.(K)^s.∏{i∈[0,m]}(V_i)^a_i
#[derive(Debug, Clone, Copy)]
pub struct BInG2<'a, E: Pairing> {
    /// Z is `b_g2_query[0]`
    pub Z: E::G2Affine,
    /// K is `delta_g2`
    pub K: E::G2Affine,
    /// BG2 is `beta_g2`
    pub BG2: E::G2Affine,
    /// V is `b_g2_query[1..]`
    pub V: &'a [E::G2Affine],
    /// a is `assignment`
    pub a: &'a [E::ScalarField],
    pub s: E::ScalarField,
    pub pp: &'a PackedSharingParams<E::ScalarField>,
}

impl<'a, E: Pairing> BInG2<'a, E> {
    /// Computes B
    pub async fn compute<Net: MpcNet>(
        self,
        msm_mask: &MsmMask<E::G2>,
        net: &Net,
        sid: MultiplexedStreamID,
    ) -> Result<E::G2, MpcNetError> {
        // We use variables (Z, K, BG2, (V_i){i∈[0,m]}) to denote elements in G2
        // We also assume that all the servers computing the proof
        // get Z, K, BG2 in the clear and only receive packed shares of the remaining elements
        // specifically, each server gets a share of (V_i)^a_i for i∈[0,Q-1].
        //
        // Given packed shares of V_i and av_i terms, the servers can use πMSM (dmsm) to compute ∏{i∈[0,Q−1]}(V_i)^a_i.
        // Since the output of MSM are regular shares, they can then be combined with Z, K, BG2 and regular shares
        // of s to get regular shares of B in G2.
        // Calculate (K)^s
        let v0 = self.K * self.s;
        // Calculate Z.(K)^s
        let v1 = self.Z + v0;
        // Calculate ∏{i∈[0,m]}(V_i)^a_i using dmsm
        let prod =
            d_msm::<E::G2, _>(self.V, self.a, msm_mask, self.pp, net, sid)
                .await?;

        let B = (v1 + prod) + self.BG2;

        Ok(B)
    }
}

/// C = (∏{i∈[l+1,m]}(W_i)^a_i)(∏{i∈[0,Q−2]}(U_i)^h_i).A^s.M^r
#[derive(Debug, Clone, Copy)]
pub struct C<'a, E: Pairing> {
    /// A in G1
    ///
    /// See [`A`] for details
    pub A: E::G1,
    /// B in G1
    ///
    /// See [`BInG1`] for details
    pub B: E::G1,
    pub s: E::ScalarField,
    pub r: E::ScalarField,
    /// M is `delta_g1`
    pub M: E::G1Affine,
    /// W is `l_query`
    pub W: &'a [E::G1Affine],
    /// U is `h_query`
    pub U: &'a [E::G1Affine],
    /// H is `b_g1_query[1..]`
    pub H: &'a [E::G1Affine],
    pub pp: &'a PackedSharingParams<E::ScalarField>,
    /// a is `input_assignment`
    pub a: &'a [E::ScalarField],
    /// ax is `aux_assignment`
    pub ax: &'a [E::ScalarField],
    /// h is `h` duh!
    pub h: &'a [E::ScalarField],
}

impl<'a, E: Pairing> C<'a, E> {
    /// Computes C
    pub async fn compute<Net: MpcNet>(
        self,
        msm_mask: &[MsmMask<E::G1>; 2],
        net: &Net,
    ) -> Result<E::G1, MpcNetError> {
        // We use variables (A, M, ∏{i∈[l+1,m]}(W_i)^a_i, ∏{i∈[0,Q−2]}(U_i)h_i, ∏{i∈[0,m]}(H_i)^a_i)
        // to denote elements in G1. We also assume that all the servers computing the proof
        // get A, M, s, r and h in the clear and only receive packed shares of the remaining elements.

        const CHANNEL0: MultiplexedStreamID = MultiplexedStreamID::Zero;
        const CHANNEL1: MultiplexedStreamID = MultiplexedStreamID::One;

        // Calculate ∏{i∈[l+1,m]}(W_i)^a_i using dmsm
        // NOTE: this `l_aux_acc`
        let w = d_msm::<E::G1, _>(
            self.W,
            self.ax,
            &msm_mask[0],
            self.pp,
            net,
            CHANNEL0,
        );
        // Calculate ∏{i∈[0,Q−2]}(U_i)^h_i using dmsm
        // NOTE: this `h_acc`
        let u = d_msm::<E::G1, _>(
            self.U,
            self.h,
            &msm_mask[1],
            self.pp,
            net,
            CHANNEL1,
        );
        let (w, u) = tokio::try_join!(w, u)?;

        let r_s_delta_g1 = self.M * (self.r * self.s);
        // Calculate A^s
        let s_g_a = self.A * self.s;
        // Calculate B(in G1)^r
        let r_g1_b = self.B * self.r;
        // finally compute C
        let C = s_g_a + r_g1_b - r_s_delta_g1 + w + u;
        Ok(C)
    }
}
