use ark_ff::FftField;
use ark_std::{end_timer, start_timer};
use secret_sharing::pss::PackedSharingParams;

pub fn pack_vec<F: FftField>(
    secrets: &Vec<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<Vec<F>> {
    debug_assert_eq!(secrets.len() % pp.l, 0, "Mismatch of size in pack_vec");
    let pack_shares_timer = start_timer!(|| "Packing shares");

    // pack shares
    let shares = secrets
        .chunks(pp.l)
        .map(|x| pp.pack_from_public(x.to_vec()))
        .collect::<Vec<_>>();

    end_timer!(pack_shares_timer);
    shares
}
pub fn transpose<T: Clone>(matrix: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!matrix.is_empty());
    let cols = matrix[0].len();
    let rows = matrix.len();

    let mut result: Vec<Vec<T>> = vec![vec![matrix[0][0].clone(); rows]; cols];

    for c in 0..cols {
        for r in 0..rows {
            result[c][r] = matrix[r][c].clone();
        }
    }
    result
}
