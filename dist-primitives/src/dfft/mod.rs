use crate::utils::pack::{pack_vec, transpose};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::log2;
use mpc_net::ser_net::MpcSerNet;
use mpc_net::{MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::mem;

#[cfg(test)]
pub mod tests;

/// Masks used in d_fft/d_ifft
/// Note that this only contains one share of the mask
#[derive(Clone)]
pub struct FftMask<F: FftField + PrimeField> {
    pub in_mask: Vec<F>,
    pub out_mask: Vec<F>,
}

impl<F: FftField + PrimeField> FftMask<F> {
    pub fn new(in_mask: Vec<F>, out_mask: Vec<F>) -> Self {
        Self { in_mask, out_mask }
    }

    /// Samples a random FftMask and returns the shares of n parties
    /// Depending on g, gen, and rearrange, this can be used for various
    /// configurations of FFT/IFFT.
    /// m denotes size of the domain
    pub fn sample(
        rearrange: bool,
        g: F,
        gen: F,
        m: usize,
        pp: &PackedSharingParams<F>,
        rng: &mut impl rand::Rng,
    ) -> Vec<Self> {
        let mut mask_values = Vec::new();
        for _ in 0..m {
            mask_values.push(F::rand(rng));
        }

        let in_mask_values = mask_values.clone();
        let in_mask_shares = transpose(pack_vec(&in_mask_values, pp));

        fft2_in_place(&mut mask_values, pp, gen); // s1 constrains final output now

        if g != F::one() {
            Radix2EvaluationDomain::<F>::distribute_powers(&mut mask_values, g);
        }

        // negate the mask_values (so that it just needs to be added to output shares)
        mask_values.iter_mut().for_each(|x| *x = -*x);

        // Optionally rearrange to get ready for next FFT/IFFT
        // Saves one round of communication by doing it at the King in the previous FFT/IFFT
        let out_mask_shares = if rearrange {
            fft_in_place_rearrange(&mut mask_values);
            let mut out_shares: Vec<Vec<F>> = Vec::new();
            for i in 0..mask_values.len() / pp.l {
                out_shares.push(
                    pp.pack(
                        mask_values
                            .iter()
                            .skip(i)
                            .step_by(mask_values.len() / pp.l)
                            .cloned()
                            .collect::<Vec<_>>(),
                        rng,
                    ),
                );
            }
            transpose(out_shares)
        } else {
            transpose(pack_vec(&mask_values, pp))
        };

        in_mask_shares
            .into_iter()
            .zip(out_mask_shares.iter())
            .map(|(in_mask_share, out_mask_share)| {
                Self::new(in_mask_share, out_mask_share.clone())
            })
            .collect()
    }
}

/// Takes as input packed shares of evaluations a polynomial over dom and outputs shares of the FFT of the polynomial
/// rearrange: whether or not to rearrange output shares in preparation for another fourier transform
pub async fn d_fft<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    mut pcoeff_share: Vec<F>,
    fft_mask: &FftMask<F>,
    rearrange: bool,
    dom: &D,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MpcNetError> {
    debug_assert_eq!(
        pcoeff_share.len() * pp.l,
        dom.size(),
        "Mismatch of size in FFT, {}, {}.",
        pcoeff_share.len() * pp.l,
        dom.size()
    );

    // Parties apply FFT1 locally
    fft1_in_place(&mut pcoeff_share, pp, dom.group_gen());
    // King applies FFT2 and parties receive shares of evals
    fft2_with_rearrange(
        pcoeff_share,
        fft_mask,
        rearrange,
        F::one(),
        pp,
        dom.group_gen(),
        net,
        sid,
    )
    .await
}

/// additionally distribute powers of g over the resulting coefficients
pub async fn d_ifft<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    mut peval_share: Vec<F>,
    fft_mask: &FftMask<F>,
    rearrange: bool,
    dom: &D,
    g: F,
    pp: &PackedSharingParams<F>,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MpcNetError> {
    debug_assert_eq!(
        peval_share.len() * pp.l,
        dom.size(),
        "Mismatch of size in IFFT, {}, {}.",
        peval_share.len() * pp.l,
        dom.size()
    );

    peval_share.iter_mut().for_each(|x| *x *= dom.size_inv());

    // Parties apply FFT1 locally
    fft1_in_place(&mut peval_share, pp, dom.group_gen_inv());
    // King applies FFT2 and parties receive shares of evals
    fft2_with_rearrange(
        peval_share,
        fft_mask,
        rearrange,
        g,
        pp,
        dom.group_gen_inv(),
        net,
        sid,
    )
    .await
}

////////////////////////////////////////////////////////////////////////////////////////////////////
fn fft1_in_place<F: FftField + PrimeField>(
    px: &mut Vec<F>,
    pp: &PackedSharingParams<F>,
    gen: F,
) {
    // FFT1 computation done locally on a vector of shares
    // debug_assert_eq!(
    //     dom.group_gen_inv().pow([(px.len() * pp.l) as u64]),
    //     F::one(),
    //     "Mismatch of size in FFT1, input:{}",
    //     px.len()
    // );

    let dom_size = px.len() * pp.l;

    // fft1
    for i in (log2(pp.l) + 1..=log2(dom_size)).rev() {
        let poly_size = dom_size / 2usize.pow(i);
        let factor_stride = gen.pow([2usize.pow(i - 1) as u64]);
        let mut factor = factor_stride;
        for k in 0..poly_size {
            for j in 0..2usize.pow(i - 1) / pp.l {
                let x = px[(2 * j) * (poly_size) + k];
                let y = px[(2 * j + 1) * (poly_size) + k] * factor;
                px[j * (2 * poly_size) + k] = x + y;
                px[j * (2 * poly_size) + k + poly_size] = x - y;
            }
            factor *= factor_stride;
        }
    }
}

fn fft2_in_place<F: FftField + PrimeField>(
    s1: &mut Vec<F>,
    pp: &PackedSharingParams<F>,
    gen: F,
) {
    let dom_size = s1.len();
    // King applies fft2, packs the vectors as desired and sends shares to parties
    let mut s2 = vec![F::zero(); s1.len()]; //Remove this time permitting

    // fft2
    for i in (1..=log2(pp.l)).rev() {
        let poly_size = dom_size / 2usize.pow(i);
        let factor_stride = gen.pow([2usize.pow(i - 1) as u64]);
        let mut factor = factor_stride;
        for k in 0..poly_size {
            for j in 0..2usize.pow(i - 1) {
                let x = s1[k * (2usize.pow(i)) + 2 * j];
                let y = s1[k * (2usize.pow(i)) + 2 * j + 1] * factor;
                s2[k * (2usize.pow(i - 1)) + j] = x + y;
                s2[(k + poly_size) * (2usize.pow(i - 1)) + j] = x - y;
            }
            factor *= factor_stride;
        }
        mem::swap(s1, &mut s2);
    }

    s1.rotate_right(1);
}

/// Send shares after fft1 to king who finishes the protocol and returns packed shares
async fn fft2_with_rearrange<F: FftField + PrimeField, Net: MpcSerNet>(
    px: Vec<F>,
    fft_mask: &FftMask<F>,
    rearrange: bool,
    g: F,
    pp: &PackedSharingParams<F>,
    gen: F,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MpcNetError> {
    // King applies FFT2 with rearrange
    let rng = &mut ark_std::test_rng();
    let mbyl = px.len();

    let out = px
        .iter()
        .zip(fft_mask.in_mask.iter())
        .map(|(x, m)| *x + *m)
        .collect::<Vec<_>>();

    let received_shares = net
        .client_send_or_king_receive_serialized(&out, sid, pp.t)
        .await?;

    let king_answer = received_shares.map(|rs| {
        let all_shares = transpose(rs.shares);
        let mut s1: Vec<F> = vec![F::zero(); out.len() * pp.l];

        for (i, share) in (0..mbyl).zip(all_shares) {
            let tmp = pp.unpack_missing_shares(&share, &rs.parties);

            for j in 0..pp.l {
                s1[i * pp.l + j] = tmp[j];
            }
        }

        fft2_in_place(&mut s1, pp, gen); // s1 constrains final output now

        if g != F::one() {
            Radix2EvaluationDomain::<F>::distribute_powers(&mut s1, g);
        }

        // Optionally rearrange to get ready for next FFT/IFFT
        // Saves one round of communication by doing it at the King in the previous FFT/IFFT
        if rearrange {
            fft_in_place_rearrange(&mut s1);
            let mut out_shares: Vec<Vec<F>> = Vec::new();
            for i in 0..s1.len() / pp.l {
                out_shares.push(
                    // This will cause issues with memory benchmarking since it assumes everyone creates this instead of receiving it from dealer
                    pp.pack(
                        s1.iter()
                            .skip(i)
                            .step_by(s1.len() / pp.l)
                            .cloned()
                            .collect::<Vec<_>>(),
                        rng,
                    ),
                );
            }
            transpose(out_shares)
        } else {
            transpose(pack_vec(&s1, pp))
        }
    });

    drop(px);

    let out_share = net
        .client_receive_or_king_send_serialized(king_answer, sid)
        .await?;

    // unmask
    let out_share = out_share
        .iter()
        .zip(fft_mask.out_mask.iter())
        .map(|(x, m)| *x + *m)
        .collect::<Vec<_>>();

    Ok(out_share)
}

pub fn fft_in_place_rearrange<F: FftField + PrimeField>(data: &mut Vec<F>) {
    let mut target = 0;
    for pos in 0..data.len() {
        if target > pos {
            data.swap(target, pos)
        }
        let mut mask = data.len() >> 1;
        while target & mask != 0 {
            target &= !mask;
            mask >>= 1;
        }
        target |= mask;
    }
}
