use crate::{dpoly_commit::PackPolyCk, PlonkDomain};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, UniformRand};
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer, One, Zero};
use dist_primitives::{
    dfft::{d_fft, d_ifft},
    dpp::d_pp,
    utils::deg_red::deg_red,
};
use mpc_net::{MpcMultiNet as Net, MpcNet};
use rand::Rng;
use secret_sharing::pss::PackedSharingParams;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PackProvingKey<E: Pairing> {
    pub ql: Vec<E::ScalarField>,
    pub qr: Vec<E::ScalarField>,
    pub qm: Vec<E::ScalarField>,
    pub qo: Vec<E::ScalarField>,
    pub qc: Vec<E::ScalarField>,
    pub s1: Vec<E::ScalarField>,
    pub s2: Vec<E::ScalarField>,
    pub s3: Vec<E::ScalarField>,
}

impl<E: Pairing> PackProvingKey<E> {
    pub fn new<R: Rng>(
        n_gates: usize,
        rng: &mut R,
        pp: &PackedSharingParams<E::ScalarField>,
    ) -> Self {
        let outer_time = start_timer!(|| "Dummy CRS");

        let mut qm: Vec<E::ScalarField> = vec![E::ScalarField::rand(rng); 8 * n_gates / pp.l];
        let mut ql: Vec<E::ScalarField> = qm.clone();
        let mut qr: Vec<E::ScalarField> = qm.clone();
        let mut qo: Vec<E::ScalarField> = qm.clone();
        let mut qc: Vec<E::ScalarField> = qm.clone();
        let mut s1: Vec<E::ScalarField> = qm.clone();
        let mut s2: Vec<E::ScalarField> = qm.clone();
        let mut s3: Vec<E::ScalarField> = qm.clone();

        for i in 0..qm.len() {
            qm[i] = E::ScalarField::rand(rng);
            ql[i] = E::ScalarField::rand(rng);
            qr[i] = E::ScalarField::rand(rng);
            qo[i] = E::ScalarField::rand(rng);
            qc[i] = E::ScalarField::rand(rng);
            s1[i] = E::ScalarField::rand(rng);
            s2[i] = E::ScalarField::rand(rng);
            s3[i] = E::ScalarField::rand(rng);
        }

        end_timer!(outer_time);

        PackProvingKey {
            qm,
            ql,
            qr,
            qo,
            qc,
            s1,
            s2,
            s3,
        }
    }
}

pub fn d_plonk_test<E: Pairing>(
    pd: &PlonkDomain<E::ScalarField>,
    pp: &PackedSharingParams<E::ScalarField>,
) {
    let mbyl = pd.n_gates / pp.l;
    if Net::am_king() {
        println!("mbyl: {}", mbyl);
    }
    // Generate CRS ===========================================
    if Net::am_king() {
        println!("Generating CRS===============================");
    }
    let rng = &mut ark_std::test_rng();
    let pk = PackProvingKey::<E>::new(pd.n_gates, rng, pp);

    let ck: PackPolyCk<E> = PackPolyCk::<E>::new(pd.n_gates, rng, pp);
    let ck8: PackPolyCk<E> = PackPolyCk::<E>::new(8 * pd.n_gates, rng, pp);

    let prover_timer = start_timer!(|| "Prover");
    if Net::am_king() {
        println!("Round 1===============================");
    }
    // Round 1 ================================================
    // Commit to a, b, c

    let mut aevals = vec![E::ScalarField::rand(rng); mbyl];
    let mut bevals = aevals.clone();
    let mut cevals = aevals.clone();
    for i in 0..aevals.len() {
        aevals[i] = E::ScalarField::rand(rng);
        bevals[i] = E::ScalarField::rand(rng);
        cevals[i] = E::ScalarField::rand(rng);
    }

    println!("Committing to a, b, c");
    ck.commit(&aevals, pp);
    ck.commit(&bevals, pp);
    ck.commit(&cevals, pp);
    println!("=======================");

    println!("Extending domain of a,b,c to 8n");
    // do ifft and fft to get evals of a,b,c on the 8n domain
    let aevals8 = d_ifft(aevals.clone(), true, 8, false, &pd.gates, pp);
    let bevals8 = d_ifft(bevals.clone(), true, 8, false, &pd.gates, pp);
    let cevals8 = d_ifft(cevals.clone(), true, 8, false, &pd.gates, pp);

    let aevals8 = d_fft(aevals8, false, 1, false, &pd.gates8, pp);
    let bevals8 = d_fft(bevals8, false, 1, false, &pd.gates8, pp);
    let cevals8 = d_fft(cevals8, false, 1, false, &pd.gates8, pp);
    println!("=======================");

    if Net::am_king() {
        println!("Round 2===============================");
    }
    // Round 2 ================================================
    // Compute z
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);

    let omega = pd.gates8.element(1);
    let mut omegai = E::ScalarField::one();

    let mut num = vec![E::ScalarField::one(); mbyl];
    let mut den = vec![E::ScalarField::one(); mbyl];

    let ldpp_timer = start_timer!(|| "Local DPP");
    for i in 0..mbyl {
        // (w_j+σ∗(j)β+γ)(w_{n+j}+σ∗(n+j)β+γ)(w_{2n+j}+σ∗(2n+j)β+γ)
        den[i] = (aevals[i] + beta * pk.s1[i] + gamma)
            * (bevals[i] + beta * pk.s2[i] + gamma)
            * (cevals[i] + beta * pk.s3[i] + gamma);

        // (w_j+βωj+γ)(w_{n+j}+βk1ωj+γ)(w_{2n+j}+βk2ωj+γ)
        num[i] = (aevals[i] + beta * omegai + gamma)
            * (bevals[i] + beta * omegai + gamma)
            * (cevals[i] + beta * omegai + gamma);

        omegai *= omega;
    }
    end_timer!(ldpp_timer);
    // todo: benchmark this
    // partial products
    let zevals = d_pp(num, den, pp);

    // extend to zevals8
    let zevals8 = zevals.clone();
    let zevals8 = d_ifft(zevals8, true, 8, false, &pd.gates, pp);
    let zevals8 = d_fft(zevals8, false, 1, false, &pd.gates8, pp);

    if Net::am_king() {
        println!("Round 3===============================");
    }
    // Round 3 ================================================
    // Compute t
    let alpha = E::ScalarField::rand(rng);

    let mut tevals8 = vec![E::ScalarField::rand(rng); 8 * mbyl];

    let omega = pd.gates8.element(1);
    let omegan = pd.gates8.element(1).pow([pd.n_gates as u64]);
    let womegan = (pd.gates8.offset * pd.gates8.element(1)).pow([pd.n_gates as u64]);

    let mut omegai = E::ScalarField::one();
    let mut omegani = E::ScalarField::one();
    let mut womengani = E::ScalarField::one();

    let t_timer = start_timer!(|| "Compute t");
    for i in 0..8 * mbyl {
        // ((a(X)b(X)qM(X) + a(X)qL(X) + b(X)qR(X) + c(X)qO(X) + PI(X) + qC(X))
        tevals8[i] += aevals8[i] * bevals8[i] * pk.qm[i]
            + aevals8[i] * pk.ql[i]
            + bevals8[i] * pk.qr[i]
            + cevals8[i] * pk.qo[i]
            + pk.qc[i];

        // ((a(X) + βX + γ)(b(X) + βk1X + γ)(c(X) + βk2X + γ)z(X))*alpha
        tevals8[i] += (aevals8[i] + beta * omegai + gamma)
            * (bevals8[i] + beta * omegai + gamma)
            * (cevals8[i] + beta * omegai + gamma)
            * (omegani - E::ScalarField::one())
            * alpha;

        // - ((a(X) + βSσ1(X) + γ)(b(X) + βSσ2(X) + γ)(c(X) + βSσ3(X) + γ)z(Xω))*alpha
        tevals8[i] -= (aevals8[i] + beta * pk.s1[i] + gamma)
            * (bevals8[i] + beta * pk.s2[i] + gamma)
            * (cevals8[i] + beta * pk.s3[i] + gamma)
            * (womengani - E::ScalarField::one())
            * alpha;

        // + (z(X)−1)L1(X)*alpha^2)/Z
        // z(X) is computed using partial products
        tevals8[i] += (zevals8[i]-E::ScalarField::one())
                        *E::ScalarField::one() //todo:replace with L1
                        *alpha*alpha;

        omegai *= omega;
        omegani *= omegan;
        womengani *= womegan;
    }
    end_timer!(t_timer);

    // divide by ZH
    let tcoeffs = d_ifft(tevals8, true, 1, false, &pd.gates8, pp);
    let mut tevals8 = d_fft(tcoeffs, false, 1, false, &pd.gates8, pp); //king actually needs to truncate

    let toep_mat = E::ScalarField::from(123_u32); // packed shares of toeplitz matrix drop from sky
    tevals8.iter_mut().for_each(|x| *x *= toep_mat);

    let tevals8 = deg_red(tevals8, pp);

    if Net::am_king() {
        println!("Round 4===============================");
    }
    // Round 4 ================================================
    // commit to z and t
    // open a, b, c, s1, s2, s3, z, t
    // commit and open r = (open_a.open_b)qm + (open_a)ql + (open_b)qr + (open_c)qo + qc

    println!("Committing to z, t");
    ck.commit(&zevals, pp);
    ck8.commit(&tevals8, pp);

    println!("Opening a, b, c");
    let point = E::ScalarField::rand(rng);
    let open_a = ck.open(&aevals, point, &pd.gates, pp);
    let open_b = ck.open(&bevals, point, &pd.gates, pp);
    let open_c = ck.open(&cevals, point, &pd.gates, pp);

    println!("Opening s1, s2, s3");
    // extract every 8th element of pk.s1 using iterators
    ck.open(
        &pk.s1.iter().step_by(8).copied().collect(),
        point,
        &pd.gates,
        pp,
    );
    ck.open(
        &pk.s2.iter().step_by(8).copied().collect(),
        point,
        &pd.gates,
        pp,
    );
    ck.open(
        &pk.s3.iter().step_by(8).copied().collect(),
        point,
        &pd.gates,
        pp,
    );

    println!("Computing r");
    let r_timer = start_timer!(|| "Compute r");
    let open_ab = open_a * open_b;
    let mut revals = vec![E::ScalarField::zero(); mbyl];
    for (i, reval) in revals.iter_mut().enumerate().take(mbyl) {
        *reval = open_ab * pk.qm[i]
            + open_a * pk.ql[i]
            + open_b * pk.qr[i]
            + open_c * pk.qo[i]
            + pk.qc[i];
    }
    end_timer!(r_timer);

    println!("Committing to r");
    ck.commit(&revals, pp);
    ck.open(&revals, point, &pd.gates, pp);

    end_timer!(prover_timer);
}
