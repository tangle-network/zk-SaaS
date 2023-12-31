use ark_ff::Field;
use std::mem;

pub fn eval<F>(p: &[F], x: F) -> F
where
    F: Field,
{
    // Horner evaluation
    p.iter()
        .rev()
        .fold(F::zero(), |acc, &coeff| acc * x + coeff)
}

pub fn eval_many<F>(p: &[F], xs: &[F]) -> Vec<F>
where
    F: Field,
{
    xs.iter().map(|x| eval(p, *x)).collect()
}

pub fn syn_div<F>(p: &[F], a: usize, b: F) -> Vec<F>
where
    F: Field,
{
    let mut result = p.to_vec();
    syn_div_in_place(&mut result, a, b);
    result
}

pub fn syn_div_in_place<F>(p: &mut [F], a: usize, b: F)
where
    F: Field,
{
    assert!(a != 0, "divisor degree cannot be zero");
    assert!(b != F::zero(), "constant cannot be zero");
    assert!(
        p.len() > a,
        "divisor degree cannot be greater than dividend size"
    );

    if a == 1 {
        // if we are dividing by (x - `b`), we can use a single variable to keep track
        // of the remainder; this way, we can avoid shifting the values in the slice later
        let mut c = F::zero();
        for coeff in p.iter_mut().rev() {
            *coeff += b * c;
            mem::swap(coeff, &mut c);
        }
    } else {
        // if we are dividing by a polynomial of higher power, we need to keep track of the
        // full remainder. we do that in place, but then need to shift the values at the end
        // to discard the remainder
        let degree_offset = p.len() - a;
        if b == F::one() {
            // if `b` is 1, no need to multiply by `b` in every iteration of the loop
            for i in (0..degree_offset).rev() {
                p[i] += p[i + a];
            }
        } else {
            for i in (0..degree_offset).rev() {
                p[i] += p[i + a] * b;
            }
        }
        // discard the remainder
        p.copy_within(a.., 0);
        p[degree_offset..].fill(F::zero());
    }
}

// HELPER FUNCTIONS
// ================================================================================================
pub fn get_zero_roots<F: Field>(xs: &[F]) -> Vec<F> {
    let mut result = vec![F::zero(); xs.len() + 1];
    let mut n = result.len();
    n -= 1;
    result[n] = F::ONE;

    for i in 0..xs.len() {
        n -= 1;
        result[n] = F::ZERO;
        #[allow(clippy::assign_op_pattern)]
        for j in n..xs.len() {
            result[j] = result[j] - result[j + 1] * xs[i];
        }
    }

    result
}
