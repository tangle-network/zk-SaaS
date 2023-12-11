use crate::{
    channel::MpcSerNet,
    utils::pack::{pack_vec, transpose},
};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::log2;
use log::debug;
use mpc_net::{MpcNetError, MultiplexedStreamID};
use secret_sharing::pss::PackedSharingParams;
use std::mem;

/// Takes as input packed shares of evaluations a polynomial over dom and outputs shares of the FFT of the polynomial
/// rearrange: whether or not to rearrange output shares
pub async fn d_fft<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    mut pcoeff_share: Vec<F>,
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
    fft1_in_place(&mut pcoeff_share, pp, dom.group_gen(), &net);
    // King applies FFT2 and parties receive shares of evals
    fft2_with_rearrange(
        pcoeff_share,
        rearrange,
        F::one(),
        pp,
        dom.group_gen(),
        net,
        sid,
    )
    .await
}

/// additionally distribute powers of domain.offset over the resulting coefficients
/// providing as input the coset domain will help with carrying out coset-FFT
pub async fn d_ifft<
    F: FftField + PrimeField,
    D: EvaluationDomain<F>,
    Net: MpcSerNet,
>(
    mut peval_share: Vec<F>,
    rearrange: bool,
    dom: &D,
    offset: F,
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
    fft1_in_place(&mut peval_share, pp, dom.group_gen_inv(), &net);
    // King applies FFT2 and parties receive shares of evals
    fft2_with_rearrange(
        peval_share,
        rearrange,
        offset,
        pp,
        dom.group_gen_inv(),
        net,
        sid,
    )
    .await
}

////////////////////////////////////////////////////////////////////////////////////////////////////
fn fft1_in_place<
    F: FftField + PrimeField,
    Net: MpcSerNet,
>(
    px: &mut Vec<F>,
    pp: &PackedSharingParams<F>,
    gen: F,
    net: &Net,
) {
    // FFT1 computation done locally on a vector of shares
    // debug_assert_eq!(
    //     dom.group_gen_inv().pow([(px.len() * pp.l) as u64]),
    //     F::one(),
    //     "Mismatch of size in FFT1, input:{}",
    //     px.len()
    // );

    let dom_size = px.len() * pp.l;

    if net.is_king() {
        debug!("Applying fft1");
    }

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

    if net.is_king() {
        debug!("Finished fft1");
    }
}

fn fft2_in_place<
    F: FftField + PrimeField,
    Net: MpcSerNet,
>(
    s1: &mut Vec<F>,
    pp: &PackedSharingParams<F>,
    gen: F,
    net: &Net,
) {
    let dom_size = s1.len();
    // King applies fft2, packs the vectors as desired and sends shares to parties
    let mut s2 = vec![F::zero(); s1.len()]; //Remove this time permitting

    if net.is_king() {
        debug!("Applying fft2");
    }

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

    if net.is_king() {
        debug!("Finished fft2");
    }
}

/// Send shares after fft1 to king who finishes the protocol and returns packed shares
async fn fft2_with_rearrange<
    F: FftField + PrimeField,
    Net: MpcSerNet,
>(
    px: Vec<F>,
    rearrange: bool,
    offset: F,
    pp: &PackedSharingParams<F>,
    gen: F,
    net: &Net,
    sid: MultiplexedStreamID,
) -> Result<Vec<F>, MpcNetError> {
    // King applies FFT2 with rearrange

    let mbyl = px.len();

    let received_shares = net.send_to_king(&px, sid).await?;

    let king_answer = received_shares.map(|all_shares| {
        let all_shares = transpose(all_shares);
        let mut s1: Vec<F> = vec![F::zero(); px.len() * pp.l];

        for (i, share) in (0..mbyl).zip(all_shares) {
            //todo: avoid always running unpack2 but this makes the code messy with another flag
            let tmp = pp.unpack2(share);

            for j in 0..pp.l {
                s1[i * pp.l + j] = tmp[j];
            }
        }

        fft2_in_place(&mut s1, pp, gen, &net); // s1 constrains final output now

        if !(offset == F::one()) {
            Radix2EvaluationDomain::<F>::distribute_powers(&mut s1, offset);
        }

        // Optionally rearrange to get ready for next FFT/IFFT
        // Saves one round of communication by doing it at the King in the previous FFT/IFFT
        if rearrange {
            fft_in_place_rearrange(&mut s1);
            let mut out_shares: Vec<Vec<F>> = Vec::new();
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
            transpose(out_shares)
        } else {
            transpose(pack_vec(&s1, pp))
        }
    });

    drop(px);

    let got_from_king = net.recv_from_king(king_answer, sid).await?;

    Ok(got_from_king)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr as F;
    use ark_poly::Radix2EvaluationDomain;
    use ark_std::{UniformRand, One};
    use mpc_net::LocalTestNet;
    use mpc_net::MpcNet;

    const L: usize = 2;
    const M: usize = L * 4;

    #[tokio::test]
    async fn d_ifft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut x = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        eprint!("x = [");
        (0..M).for_each(|i| {
            eprint!("{}", x[i]);
            if i != M - 1 {
                eprint!(", ");
            }
        });
        eprintln!("]");

        eprintln!("Computed x evals done ...");
        eprintln!("Computing actual x evals by using ifft ...");
        let actual_x_evals = constraint.ifft(&x);
        eprintln!("Actual x coeff done ...");

        fft_in_place_rearrange(&mut x);
        let mut pevals: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            pevals.push(
                x.iter()
                    .skip(i)
                    .step_by(M / pp.l)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            pp.pack_from_public_in_place(&mut pevals[i]);
        }

        eprintln!("Running d_ifft ...");
        let result = network
            .simulate_network_round(
                (pevals, pp, constraint),
                |net, (pcoeff, pp, constraint)| async move {
                    let idx = net.party_id() as usize;
                    let peval_share =
                        pcoeff.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    d_ifft(
                        peval_share,
                        false,
                        &constraint,
                        F::one(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;
        eprintln!("d_ifft done ...");
        eprintln!("Computing x evals from the shares ...");
        let computed_x_evals = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        eprintln!("Comparing the computed x eval with actual x eval ...");
        eprintln!("```");
        for i in 0..M {
            eprintln!("ACTL: {}", actual_x_evals[i]);
            eprintln!("COMP: {}", computed_x_evals[i]);
            if actual_x_evals[i] == computed_x_evals[i] {
                eprintln!("..{i}th element Matched ✅");
            } else {
                eprintln!("..{i}th element Mismatched ❌");
                // search for the element in actual_x_coeff
                let found = computed_x_evals
                    .iter()
                    .position(|&x| x == actual_x_evals[i]);
                match found {
                    Some(i) => eprintln!(
                        "....However, it has been found at index: {i} ⚠️"
                    ),
                    None => eprintln!("....and Not found at all 🤔"),
                }
            }
        }
        eprintln!("```");

        assert_eq!(actual_x_evals, computed_x_evals);
    }

    #[tokio::test]
    async fn d_fft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut x = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let actual_x_coeff = constraint.fft(&x);
        eprint!("x = [");
        (0..M).for_each(|i| {
            eprint!("{}", x[i]);
            if i != M - 1 {
                eprint!(", ");
            }
        });
        eprintln!("]");

        fft_in_place_rearrange(&mut x);

        let mut pcoeff: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            pcoeff.push(
                x.iter()
                    .skip(i)
                    .step_by(M / pp.l)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            pp.pack_from_public_in_place(&mut pcoeff[i]);
        }
        eprintln!("Running d_fft ...");
        let result = network
            .simulate_network_round(
                (pcoeff, pp, constraint),
                |net, (pcoeff, pp, constraint)| async move {
                    let idx = net.party_id() as usize;
                    let pcoeff_share =
                        pcoeff.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    d_fft(
                        pcoeff_share,
                        false,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;

        let computed_x_coeff = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        eprintln!("Comparing the computed x coeff with actual x coeff ...");
        eprintln!("```");
        for i in 0..M {
            eprintln!("ACTL: {}", actual_x_coeff[i]);
            eprintln!("COMP: {}", computed_x_coeff[i]);
            if actual_x_coeff[i] == computed_x_coeff[i] {
                eprintln!("..{i}th element Matched ✅");
            } else {
                eprintln!("..{i}th element Mismatched ❌");
                // search for the element in actual_x_coeff
                let found = computed_x_coeff
                    .iter()
                    .position(|&x| x == actual_x_coeff[i]);
                match found {
                    Some(i) => eprintln!(
                        "....However, it has been found at index: {i} ⚠️"
                    ),
                    None => eprintln!("....and Not found at all 🤔"),
                }
            }
        }
        eprintln!("```");
        assert_eq!(actual_x_coeff, computed_x_coeff);
    }

    #[tokio::test]
    async fn d_ifftxd_fft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut x = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let expected_x = x.clone();
        eprint!("x = [");
        (0..M).for_each(|i| {
            eprint!("{}", x[i]);
            if i != M - 1 {
                eprint!(", ");
            }
        });
        eprintln!("]");

        fft_in_place_rearrange(&mut x);
        let mut pevals: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            pevals.push(
                x.iter()
                    .skip(i)
                    .step_by(M / pp.l)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            pp.pack_from_public_in_place(&mut pevals[i]);
        }

        eprintln!("Running d_ifftxd_ifft ...");
        let result = network
            .simulate_network_round(
                (pevals, pp, constraint),
                |net, (pcoeff, pp, constraint)| async move {
                    let idx = net.party_id() as usize;
                    let peval_share =
                        pcoeff.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    let p_coeff = d_ifft(
                        peval_share,
                        true,
                        &constraint,
                        F::one(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    d_fft(
                        p_coeff,
                        false,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                },
            )
            .await;
        eprintln!("d_ifftxd_fft done ...");
        eprintln!("Computing x evals from the shares ...");
        let computed_x = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        eprintln!("Comparing the computed x eval with actual x eval ...");
        eprintln!("```");
        for i in 0..M {
            eprintln!("ACTL: {}", expected_x[i]);
            eprintln!("COMP: {}", computed_x[i]);
            if expected_x[i] == computed_x[i] {
                eprintln!("..{i}th element Matched ✅");
            } else {
                eprintln!("..{i}th element Mismatched ❌");
                // search for the element in actual_x_coeff
                let found = computed_x.iter().position(|&x| x == expected_x[i]);
                match found {
                    Some(i) => eprintln!(
                        "....However, it has been found at index: {i} ⚠️"
                    ),
                    None => eprintln!("....and Not found at all 🤔"),
                }
            }
        }
        eprintln!("```");

        assert_eq!(expected_x, computed_x);
    }

    #[tokio::test]
    async fn coset_d_ifftxd_fft_works() {
        let rng = &mut ark_std::test_rng();
        let pp = PackedSharingParams::<F>::new(L);
        let constraint = Radix2EvaluationDomain::<F>::new(M).unwrap();
        let constraint_coset = constraint.get_coset(F::GENERATOR).unwrap();
        let network = LocalTestNet::new_local_testnet(pp.n).await.unwrap();
        let mut x = (0..M).map(|_| F::rand(rng)).collect::<Vec<_>>();
        let expected_x = x.clone();

        fft_in_place_rearrange(&mut x);
        let mut pevals: Vec<Vec<F>> = Vec::new();
        for i in 0..M / pp.l {
            pevals.push(
                x.iter()
                    .skip(i)
                    .step_by(M / pp.l)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            pp.pack_from_public_in_place(&mut pevals[i]);
        }

        eprintln!("Running coset_d_ifftxd_ifft ...");
        let result = network
            .simulate_network_round(
                (pevals, pp, constraint, constraint_coset),
                |net, (pcoeff, pp, constraint, constraint_coset)| async move {
                    let idx = net.party_id() as usize;
                    let peval_share =
                        pcoeff.iter().map(|x| x[idx]).collect::<Vec<_>>();
                    // starting with evals over dom
                    let p_coeff = d_ifft(
                        peval_share,
                        true,
                        &constraint,
                        constraint_coset.coset_offset(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    let coset_peval_share = d_fft(
                        p_coeff,
                        true,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    // obtained evals over coset_dom
                    let p_coeff = d_ifft(
                        coset_peval_share,
                        true,
                        &constraint,
                        constraint_coset.coset_offset_inv(),
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    d_fft(
                        p_coeff,
                        false,
                        &constraint,
                        &pp,
                        &net,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                    // back to evals over dom
                },
            )
            .await;
        eprintln!("coset_d_ifftxd_fft done ...");
        eprintln!("Computing x evals from the shares ...");
        let computed_x = transpose(result)
            .into_iter()
            .flat_map(|x| pp.unpack(x))
            .collect::<Vec<_>>();

        assert_eq!(expected_x, computed_x);
    }
}
