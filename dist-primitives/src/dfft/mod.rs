use crate::{
    channel::MpcSerNet,
    utils::pack::{pack_vec, transpose},
};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, log2, start_timer};
use log::debug;
use mpc_net::{MpcMultiNet as Net, MpcNet};
use secret_sharing::pss::PackedSharingParams;
use std::mem;

/// Takes as input packed shares of evaluations a polynomial over dom and outputs shares of the FFT of the polynomial
/// rearrange: whether or not to rearrange output shares
/// pad: whether or not to pad output shares with zeros
/// degree2: whether or not to do degree reduction n the input shares
pub fn d_fft<F: FftField + PrimeField>(
    mut pcoeff_share: Vec<F>,
    rearrange: bool,
    pad: usize,
    degree2: bool,
    dom: &Radix2EvaluationDomain<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<F> {
    debug_assert_eq!(
        pcoeff_share.len() * pp.l,
        dom.size(),
        "Mismatch of size in FFT, {}, {}.",
        pcoeff_share.len() * pp.l,
        dom.size()
    );

    // Parties apply FFT1 locally
    fft1_in_place(&mut pcoeff_share, dom, pp);
    // King applies FFT2 and parties receive shares of evals
    fft2_with_rearrange_pad(pcoeff_share, rearrange, pad, degree2, dom, pp)
}

pub fn d_ifft<F: FftField + PrimeField>(
    mut peval_share: Vec<F>,
    rearrange: bool,
    pad: usize,
    degree2: bool,
    dom: &Radix2EvaluationDomain<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<F> {
    debug_assert_eq!(
        peval_share.len() * pp.l,
        dom.size(),
        "Mismatch of size in IFFT, {}, {}.",
        peval_share.len() * pp.l,
        dom.size()
    );

    let sizeinv = F::from(dom.size).inverse().unwrap();
    peval_share.iter_mut().for_each(|x| *x *= sizeinv);

    // Parties apply FFT1 locally
    fft1_in_place(&mut peval_share, dom, pp);
    // King applies FFT2 and parties receive shares of evals
    fft2_with_rearrange_pad(peval_share, rearrange, pad, degree2, dom, pp)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
fn fft1_in_place<F: FftField + PrimeField>(
    px: &mut Vec<F>,
    dom: &Radix2EvaluationDomain<F>,
    pp: &PackedSharingParams<F>,
) {
    // FFT1 computation done locally on a vector of shares
    debug_assert_eq!(
        dom.group_gen_inv.pow([(px.len() * pp.l) as u64]),
        F::one(),
        "Mismatch of size in FFT1, input:{}",
        px.len()
    );

    let now = start_timer!(|| "FFT1");
    if Net::am_king() {
        debug!("Applying fft1");
    }

    // fft1
    for i in (log2(pp.l) + 1..=log2(dom.size())).rev() {
        let poly_size = dom.size() / 2usize.pow(i);
        let factor_stride = dom.group_gen_inv.pow([2usize.pow(i - 1) as u64]);
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

    end_timer!(now);

    if Net::am_king() {
        debug!("Finished fft1");
    }
}

fn fft2_in_place<F: FftField + PrimeField>(
    s1: &mut Vec<F>,
    dom: &Radix2EvaluationDomain<F>,
    pp: &PackedSharingParams<F>,
) {
    // King applies fft2, packs the vectors as desired and sends shares to parties

    let now = start_timer!(|| "FFT2");
    let mut s2 = vec![F::zero(); s1.len()]; //Remove this time permitting

    if Net::am_king() {
        debug!("Applying fft2");
    }

    // fft2
    for i in (1..=log2(pp.l)).rev() {
        let poly_size = dom.size() / 2usize.pow(i);
        let factor_stride = dom.group_gen_inv.pow([2usize.pow(i - 1) as u64]);
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

    // s1.rotate_right(1);

    end_timer!(now);

    if Net::am_king() {
        debug!("Finished fft2");
    }
}

/// Send shares after fft1 to king who finishes the protocol and returns packed shares
fn fft2_with_rearrange_pad<F: FftField + PrimeField>(
    px: Vec<F>,
    rearrange: bool,
    pad: usize,
    degree2: bool,
    dom: &Radix2EvaluationDomain<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<F> {
    // King applies FFT2 with rearrange

    let mbyl = px.len();
    println!("mbyl: {}", mbyl);

    let communication_timer = start_timer!(|| "ComToKing");
    let received_shares = Net::send_to_king(&px);
    end_timer!(communication_timer);

    let king_answer = received_shares.map(|all_shares| {
        let all_shares = transpose(all_shares);
        let mut s1: Vec<F> = vec![F::zero(); px.len() * pp.l];

        let open_shares_timer = start_timer!(|| "Opening shares");
        for (i, share) in (0..mbyl).zip(all_shares) {
            let tmp = if degree2 {
                pp.unpack2(share)
            } else {
                pp.unpack(share)
            };

            for j in 0..pp.l {
                s1[i * pp.l + j] = tmp[j];
            }
        }
        end_timer!(open_shares_timer);

        fft2_in_place(&mut s1, dom, pp); // s1 constains final output now

        // Optionally double length by padding zeros here
        if pad > 1 {
            s1.resize(pad * s1.len(), F::zero());
        }

        // Optionally rearrange to get ready for next FFT/IFFT
        if rearrange {
            fft_in_place_rearrange(&mut s1);
            let mut out_shares: Vec<Vec<F>> = Vec::new();
            let pack_shares_timer = start_timer!(|| "Packing shares");
            for i in 0..s1.len() / pp.l {
                out_shares.push(
                    // This will cause issues with memory benchmarking since it assumes everyone creates this instead of receiving it from dealer
                    pp.pack_from_public(
                        s1.iter()
                            .skip(i)
                            .step_by(s1.len() / pp.l)
                            .cloned()
                            .collect::<Vec<_>>(),
                    ),
                );
            }
            end_timer!(pack_shares_timer);
            transpose(out_shares)
        } else {
            transpose(pack_vec(&s1, pp))
        }
    });

    drop(px);

    let communication_timer = start_timer!(|| "ComFromKing");
    let got_from_king = Net::recv_from_king(king_answer);
    end_timer!(communication_timer);

    got_from_king
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
