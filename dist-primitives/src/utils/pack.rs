use ark_ff::FftField;
use ark_poly::domain::DomainCoeff;
use ark_std::cfg_chunks;
use rand::thread_rng;
use secret_sharing::pss::PackedSharingParams;

pub fn best_unpack<F: FftField, T: DomainCoeff<F>>(
    shares: &[T],
    parties: &[u32],
    pp: &PackedSharingParams<F>,
) -> Vec<T> {
    debug_assert_eq!(shares.len(), parties.len());
    if shares.len() == pp.n {
        pp.unpack2(shares.to_vec())
    } else {
        pp.lagrange_unpack(shares, parties)
    }
}

pub fn pack_vec<F: FftField>(
    secrets: &Vec<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<Vec<F>> {
    debug_assert_eq!(secrets.len() % pp.l, 0, "Mismatch of size in pack_vec");

    let rng = &mut thread_rng();
    
    // pack shares
    cfg_chunks!(secrets, pp.l)
        .map(|x| pp.pack(x.to_vec(), rng))
        .collect::<Vec<_>>()
}

pub fn transpose<T: Clone>(matrix: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!matrix.is_empty());
    let cols = matrix[0].len();
    let rows = matrix.len();

    let mut result: Vec<Vec<T>> = vec![vec![matrix[0][0].clone(); rows]; cols];

    for (c, column) in result.iter_mut().enumerate().take(cols) {
        for (r, row) in matrix.iter().enumerate().take(rows) {
            column[r] = row[c].clone();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpose() {
        let matrix = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let expected = vec![vec![1, 4, 7], vec![2, 5, 8], vec![3, 6, 9]];

        assert_eq!(transpose(matrix), expected);
    }
}
