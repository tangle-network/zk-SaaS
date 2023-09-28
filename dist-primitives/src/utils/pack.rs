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

pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}
