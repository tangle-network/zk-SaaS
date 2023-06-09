use ark_ec::{bls12::Bls12, pairing::Pairing, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer, One, Zero};
use groth16::ConstraintDomain;
use log::debug;
use rand::Rng;

use ark_bls12_377;
type BlsE = Bls12<ark_bls12_377::Config>;
type BlsFr = <Bls12<ark_bls12_377::Config> as Pairing>::ScalarField;

#[derive(Clone, Debug, Default, PartialEq)]
struct ProvingKey<E: Pairing> {
    pub s: Vec<E::G1Affine>,
    pub u: Vec<E::G1Affine>,
    pub v: Vec<E::G2Affine>,
    pub w: Vec<E::G1Affine>,
    pub h: Vec<E::G1Affine>,
}

fn local_dummy_crs<E: Pairing, R: Rng>(domain_size: usize, rng: &mut R) -> ProvingKey<E> {
    let outer_time = start_timer!(|| "Dummy CRS packing");

    let mut s: Vec<<E as Pairing>::G1Affine> = vec![E::G1Affine::rand(rng); domain_size];
    for i in 1..s.len() {
        s[i] = (s[i - 1] + s[i - 1]).into();
    }

    let mut u = vec![E::G1Affine::rand(rng); domain_size * 2];
    for i in 1..u.len() {
        u[i] = (u[i - 1] + u[i - 1]).into();
    }

    let mut w = vec![E::G1Affine::rand(rng); domain_size];
    for i in 1..w.len() {
        w[i] = (w[i - 1] + w[i - 1]).into();
    }

    let mut h = vec![E::G1Affine::rand(rng); domain_size];
    for i in 1..h.len() {
        h[i] = (h[i - 1] + h[i - 1]).into();
    }

    let mut v = vec![E::G2Affine::rand(rng); domain_size];
    for i in 1..v.len() {
        v[i] = (v[i - 1] + v[i - 1]).into();
    }

    end_timer!(outer_time);

    ProvingKey::<E> { s, u, v, w, h }
}

// Add preprocessing vectors of size 4m/l
// process u and v to get ready for multiplication

// Compute h = (u.v - w).t -- 2m shares
// Field operations
// u, v, w -- m + m + m
// Compute IFFT(u) -- m/l preprocessing for sending + 2m/l for receiving (output padded with zeros and re-arranged)
// Compute FFT(u) -- 2m/l for sending + 2m/l for receiving preprocessing
// Compute IFFT(v) -- m/l preprocessing for sending + 2m/l for receiving (output padded with zeros and re-arranged)
// Compute FFT(v) -- 2m/l for sending + 2m/l for receiving preprocessing
// Compute IFFT(w) -- m/l preprocessing for sending + 2m/l for receiving (output padded with zeros and re-arranged)
// Compute FFT(w) -- 2m/l for sending + 2m/l for receiving preprocessing
// u, v - 2m/l + 2m/l shares
// w - 2m/l shares
// t - 2m/l shares (Can be dropped in later by king so not contributing to memory)

// Total preprocessing -- 21m/l for u, v, w and 4m/l for computing h
// Former can be avoided if client provides 2Q evaluations of u,v,w instead of Q evaluations
// Computing h
// Compute h = (u.v - w).t -- 2m/l shares
// Send to king to pack desired coefficients of h -- 2m/l for sending + 2m/l for receiving
// (potentially all of them if we only have addition gates hence 2m/l for receiving as well)

// Group operations
// Can ignore preprocessing here as it is tiny O(l)
// Packed CRS drops in from the sky
// Do 5 MSMs to obtain shares of A, B and C
// Done

fn localgroth_test<E: Pairing>(cd: &ConstraintDomain<E::ScalarField>) {
    let mut p_eval: Vec<E::ScalarField> = vec![E::ScalarField::zero(); cd.m];
    // Shares of P, Q, W drop from the sky
    for i in 0..cd.m {
        p_eval[i] = E::ScalarField::from(i as u64);
    }
    let mut q_eval: Vec<E::ScalarField> = p_eval.clone();
    let mut w_eval: Vec<E::ScalarField> = p_eval.clone();

    let fft_section = start_timer!(|| "Field operations");

    /////////IFFT
    cd.constraint.ifft_in_place(&mut p_eval);
    cd.constraint.ifft_in_place(&mut q_eval);
    cd.constraint.ifft_in_place(&mut w_eval);

    /////////FFT
    cd.constraint2.fft_in_place(&mut p_eval);
    cd.constraint2.fft_in_place(&mut q_eval);
    cd.constraint2.fft_in_place(&mut w_eval);

    ///////////Multiply Shares
    let mut h_eval: Vec<E::ScalarField> = vec![E::ScalarField::zero(); p_eval.len()];
    let t_eval: Vec<E::ScalarField> = vec![E::ScalarField::one(); h_eval.len()];
    for i in 0..p_eval.len() {
        h_eval[i] = p_eval[i] * q_eval[i] - w_eval[i];
    }

    drop(p_eval);
    drop(q_eval);
    drop(w_eval);

    // King drops shares of t
    for i in 0..h_eval.len() {
        h_eval[i] *= t_eval[i];
    }

    ///////////IFFT
    cd.constraint2.ifft_in_place(&mut h_eval);
    end_timer!(fft_section);

    let rng = &mut ark_std::test_rng();
    let crs: ProvingKey<E> = local_dummy_crs(cd.m, rng);
    let a_share: Vec<E::ScalarField> = vec![E::ScalarField::rand(rng); crs.s.len()];

    println!(
        "s:{}, v:{}, h:{}, w:{}, u:{}, a:{}, h:{}",
        crs.s.len(),
        crs.v.len(),
        crs.h.len(),
        crs.w.len(),
        crs.u.len(),
        a_share.len(),
        h_eval.len()
    );

    let msm_section = start_timer!(|| "MSM operations");
    // Compute msm while dropping the base vectors as they are not used again
    let _pi_a_share = E::G1::msm(&crs.s, &a_share).unwrap();
    println!("s done");
    let _pi_b_share = E::G2::msm(&crs.v, &a_share).unwrap();
    println!("v done");
    let _pi_c_share1 = E::G1::msm(&crs.h, &a_share).unwrap();
    println!("h done");
    let _pi_c_share2 = E::G1::msm(&crs.w, &a_share).unwrap();
    println!("w done");
    let _pi_c_share3 = E::G1::msm(&crs.u, &h_eval).unwrap();
    println!("u done");
    let _pi_c_share = _pi_c_share1 + _pi_c_share2 + _pi_c_share3; //Additive notation for groups
                                                                  // Send _pi_a_share, _pi_b_share, _pi_c_share to client
    end_timer!(msm_section);
}

fn main() {
    debug!("Start");
    let cd = ConstraintDomain::<BlsFr>::new(1 << 15);
    localgroth_test::<BlsE>(&cd);

    debug!("Done");
}
