use ark_bls12_377::Fr;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{end_timer, start_timer, UniformRand, Zero};

pub fn msm_test<G: CurveGroup>(dom: &Radix2EvaluationDomain<G::ScalarField>) {
    let rng = &mut ark_std::test_rng();

    let mut y_pub: Vec<G::ScalarField> = vec![G::ScalarField::zero(); dom.size()];
    let mut x_pub: Vec<G> = vec![G::zero(); dom.size()];

    for i in 0..dom.size() {
        y_pub[i] = G::ScalarField::rand(rng);
        x_pub[i] = G::rand(rng);
    }

    let x_pub_aff: Vec<G::Affine> = x_pub.iter().map(|s| s.clone().into()).collect();

    let nmsm = start_timer!(|| "Ark msm");
    G::msm(&x_pub_aff.as_slice(), &y_pub.as_slice()).unwrap();
    end_timer!(nmsm);
}

fn main() {
    for i in 10..20 {
        let dom = Radix2EvaluationDomain::<Fr>::new(1 << i).unwrap();
        println!("domain size: {}", dom.size());
        msm_test::<ark_bls12_377::G1Projective>(&dom);
    }
}
