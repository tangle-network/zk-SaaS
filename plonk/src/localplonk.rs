use crate::{poly_commit::PolyCk, PlonkDomain};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, UniformRand};
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer, One, Zero};
use rand::Rng;

#[derive(Clone, Debug, Default, PartialEq)]
struct ProvingKey<E: Pairing> {
    pub ql: Vec<E::ScalarField>,
    pub qr: Vec<E::ScalarField>,
    pub qm: Vec<E::ScalarField>,
    pub qo: Vec<E::ScalarField>,
    pub qc: Vec<E::ScalarField>,
    pub s1: Vec<E::ScalarField>,
    pub s2: Vec<E::ScalarField>,
    pub s3: Vec<E::ScalarField>,
}

impl<E: Pairing> ProvingKey<E> {
    fn new<R: Rng>(n_gates: usize, rng: &mut R) -> Self {
        let outer_time = start_timer!(|| "Dummy CRS");

        let mut qm: Vec<E::ScalarField> = vec![E::ScalarField::rand(rng); 8 * n_gates];
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

        ProvingKey {
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

pub fn localplonk<E: Pairing>(pd: &PlonkDomain<E::ScalarField>) {
    // Generate CRS ===========================================
    let rng = &mut ark_std::test_rng();
    let pk = ProvingKey::<E>::new(pd.n_gates, rng);
    let ck: PolyCk<E> = PolyCk::<E>::new(pd.n_gates, rng);
    let ck8: PolyCk<E> = PolyCk::<E>::new(8 * pd.n_gates, rng);

    let prover_timer = start_timer!(|| "Prover");
    println!("Round 1===============================");
    // Round 1 ================================================
    // Commit to a, b, c
    let mut aevals = vec![E::ScalarField::rand(rng); pd.n_gates];
    let mut bevals = aevals.clone();
    let mut cevals = aevals.clone();
    for i in 0..aevals.len() {
        aevals[i] = E::ScalarField::rand(rng);
        bevals[i] = E::ScalarField::rand(rng);
        cevals[i] = E::ScalarField::rand(rng);
    }

    println!("Committing to a, b, c");
    ck.commit(&aevals);
    println!("aveals: {}", aevals.len());
    ck.commit(&bevals);
    ck.commit(&cevals);
    println!("=======================");

    println!("Extending domain of a,b,c to 8n");
    // do ifft and fft to get evals of a,b,c on the 8n domain
    let mut aevals8 = aevals.clone();
    let mut bevals8 = bevals.clone();
    let mut cevals8 = cevals.clone();

    let fft_timer = start_timer!(|| "FFT");
    pd.gates.ifft_in_place(&mut aevals8);
    pd.gates.ifft_in_place(&mut bevals8);
    pd.gates.ifft_in_place(&mut cevals8);

    pd.gates8.fft_in_place(&mut aevals8);
    pd.gates8.fft_in_place(&mut bevals8);
    pd.gates8.fft_in_place(&mut cevals8);
    end_timer!(fft_timer);

    println!("=======================");

    println!("Round 2===============================");
    // Round 2 ================================================
    // Compute z
    let beta = E::ScalarField::rand(rng);
    let gamma = E::ScalarField::rand(rng);

    let mut zevals = vec![E::ScalarField::zero(); pd.n_gates];

    let omega = pd.gates8.element(1);
    let mut omegai = E::ScalarField::one();

    let pp_timer = start_timer!(|| "PP");
    for i in 0..pd.n_gates {
        // (w_j+σ∗(j)β+γ)(w_{n+j}+σ∗(n+j)β+γ)(w_{2n+j}+σ∗(2n+j)β+γ)
        let den = (aevals[i] + beta * pk.s1[i] + gamma)
            * (bevals[i] + beta * pk.s2[i] + gamma)
            * (cevals[i] + beta * pk.s3[i] + gamma);
        let den = den.inverse().unwrap();

        // (w_j+βωj+γ)(w_{n+j}+βk1ωj+γ)(w_{2n+j}+βk2ωj+γ)
        zevals[i] = (aevals[i] + beta * omegai + gamma)
            * (bevals[i] + beta * omegai + gamma)
            * (cevals[i] + beta * omegai + gamma)
            * den;
        omegai *= omega;
    }

    // partial products
    for i in 1..pd.n_gates {
        let last = zevals[i - 1];
        zevals[i] *= last;
    }
    end_timer!(pp_timer);

    // extend to zevals8
    let fft_timer = start_timer!(|| "FFT");
    let mut zevals8 = zevals.clone();
    pd.gates.ifft_in_place(&mut zevals8);
    pd.gates8.fft_in_place(&mut zevals8);
    end_timer!(fft_timer);

    println!("Round 3===============================");
    // Round 3 ================================================
    // Compute t
    let alpha = E::ScalarField::rand(rng);

    let mut tevals8 = vec![E::ScalarField::zero(); pd.gates8.size()];

    let omega = pd.gates8.element(1);
    let omegan = pd.gates8.element(1).pow([pd.n_gates as u64]);
    let womegan = (pd.gates8.offset * pd.gates8.element(1)).pow([pd.n_gates as u64]);

    let mut omegai = E::ScalarField::one();
    let mut omegani = E::ScalarField::one();
    let mut womengani = E::ScalarField::one();

    let t_timer = start_timer!(|| "Compute t");
    for i in 0..tevals8.len() {
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
    let fft_timer = start_timer!(|| "FFT");
    let tcoeffs = pd.gates8.ifft(&tevals8);
    let mut tevals8 = pd.gates8.fft(&tcoeffs[0..7 * pd.n_gates]);
    let toep_mat = E::ScalarField::from(123_u32); // packed shares of toeplitz matrix drop from sky
    end_timer!(fft_timer);

    tevals8.iter_mut().for_each(|x| *x *= toep_mat);

    println!("Round 4===============================");
    // Round 4 ================================================
    // commit to z and t
    // open a, b, c, s1, s2, s3, z, t
    // commit and open r = (open_a.open_b)qm + (open_a)ql + (open_b)qr + (open_c)qo + qc

    ck.commit(&zevals);
    ck8.commit(&tevals8);

    let point = E::ScalarField::rand(rng);
    let open_a = ck.open(&aevals, point, &pd.gates);
    let open_b = ck.open(&bevals, point, &pd.gates);
    let open_c = ck.open(&cevals, point, &pd.gates);

    // extract every 8th element of pk.s1 using iterators
    ck.open(
        &pk.s1.iter().step_by(8).copied().collect(),
        point,
        &pd.gates,
    );
    ck.open(
        &pk.s2.iter().step_by(8).copied().collect(),
        point,
        &pd.gates,
    );
    ck.open(
        &pk.s3.iter().step_by(8).copied().collect(),
        point,
        &pd.gates,
    );

    let open_ab = open_a * open_b;
    let mut revals = vec![E::ScalarField::zero(); pd.n_gates];
    let timer_r = start_timer!(|| "Compute r");
    for (i, reval) in revals.iter_mut().enumerate().take(pd.n_gates) {
        *reval = open_ab * pk.qm[i]
            + open_a * pk.ql[i]
            + open_b * pk.qr[i]
            + open_c * pk.qo[i]
            + pk.qc[i];
    }
    end_timer!(timer_r);

    ck.commit(&revals);
    ck.open(&revals, point, &pd.gates);

    end_timer!(prover_timer);
}
