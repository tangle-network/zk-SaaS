use std::mem;

use ark_bls12_377::Fr;
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, log2, start_timer};
use dist_primitives::dfft::dfft::fft_in_place_rearrange;
use secret_sharing::pss::PackedSharingParams;

pub fn local_dfft_test<F: FftField + PrimeField>(
    pp: &PackedSharingParams<F>,
    dom: &Radix2EvaluationDomain<F>,
) {
    let mbyl: usize = dom.size() / pp.l;

    // We apply FFT on this vector
    // let mut x = vec![F::one();cd.m];
    let mut x: Vec<F> = Vec::new();
    for i in 0..dom.size() {
        x.push(F::from(i as u64));
    }

    // Output to test against
    let output = dom.fft(&x);

    // Rearranging x
    let myfft_timer = start_timer!(|| "MY FFT");

    fft_in_place_rearrange::<F>(&mut x);

    let mut px: Vec<Vec<F>> = Vec::new();
    for i in 0..mbyl {
        px.push(x.iter().skip(i).step_by(mbyl).cloned().collect::<Vec<_>>());
    }

    let mut s1 = px.clone();

    let now = start_timer!(|| "FFT1");

    // fft1
    for i in (log2(pp.l) + 1..=log2(dom.size())).rev() {
        let poly_size = dom.size() / 2usize.pow(i);
        let factor_stride = dom.element(2usize.pow(i - 1));
        let mut factor = factor_stride;
        for k in 0..poly_size {
            for j in 0..2usize.pow(i - 1) / pp.l {
                for ii in 0..pp.l {
                    let x = s1[(2 * j) * (poly_size) + k][ii];
                    let y = s1[(2 * j + 1) * (poly_size) + k][ii] * factor;
                    s1[j * (2 * poly_size) + k][ii] = x + y;
                    s1[j * (2 * poly_size) + k + poly_size][ii] = x - y;
                }
            }
            factor = factor * factor_stride;
        }
    }

    end_timer!(now);

    // psstoss
    let mut sx: Vec<F> = Vec::new();
    for i in 0..mbyl {
        sx.append(&mut s1[i]);
    }

    // fft2
    let mut s1 = sx.clone();
    let mut s2 = sx.clone();

    let now = start_timer!(|| "FFT2");

    for i in (1..=log2(pp.l)).rev() {
        let poly_size = dom.size() / 2usize.pow(i);
        let factor_stride = dom.element(2usize.pow(i - 1));
        let mut factor = factor_stride;
        for k in 0..poly_size {
            for j in 0..2usize.pow(i - 1) {
                let x = s1[k * (2usize.pow(i)) + 2 * j];
                let y = s1[k * (2usize.pow(i)) + 2 * j + 1] * factor;
                s2[k * (2usize.pow(i - 1)) + j] = x + y;
                s2[(k + poly_size) * (2usize.pow(i - 1)) + j] = x - y;
            }
            factor = factor * factor_stride;
        }
        mem::swap(&mut s1, &mut s2);
    }
    end_timer!(now);

    end_timer!(myfft_timer);

    s1.rotate_right(1);

    assert_eq!(output, s1);
}

pub fn main() {
    let pp = PackedSharingParams::<Fr>::new(2);
    let dom = Radix2EvaluationDomain::<Fr>::new(8).unwrap();
    local_dfft_test::<Fr>(&pp, &dom);
}
