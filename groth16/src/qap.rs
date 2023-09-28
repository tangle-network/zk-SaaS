use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::evaluate_constraint;
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, SynthesisError};
use ark_std::{cfg_iter, cfg_iter_mut, vec};

/// A Quadratic Arithmetic Program (QAP) that holds
/// witness reductions from R1CS.
#[derive(Debug, Clone)]
pub struct QAP<F: PrimeField, D: EvaluationDomain<F>> {
    pub num_inputs: usize,
    pub num_constraints: usize,
    /// A is also called P in the paper.
    pub a: Vec<F>,
    /// B is also called Q in the paper.
    pub b: Vec<F>,
    /// C is also called W in the paper.
    pub c: Vec<F>,
    /// Evaluation domain of the QAP.
    pub domain: D,
}

pub fn qap<F: PrimeField, D: EvaluationDomain<F>>(
    matrices: &ConstraintMatrices<F>,
    full_assignment: &[F],
) -> Result<QAP<F, D>, SynthesisError> {
    let zero = F::zero();

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let domain = D::new(num_constraints + num_inputs)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let domain_size = domain.size();

    let mut a = vec![zero; domain_size];
    let mut b = vec![zero; domain_size];

    cfg_iter_mut!(a[..num_constraints])
        .zip(cfg_iter_mut!(b[..num_constraints]))
        .zip(cfg_iter!(&matrices.a))
        .zip(cfg_iter!(&matrices.b))
        .for_each(|(((a, b), at_i), bt_i)| {
            *a = evaluate_constraint(at_i, full_assignment);
            *b = evaluate_constraint(bt_i, full_assignment);
        });

    {
        let start = num_constraints;
        let end = start + num_inputs;
        a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
    }

    let mut c = vec![zero; domain_size];
    cfg_iter_mut!(c[..num_constraints])
        .zip(&a)
        .zip(&b)
        .for_each(|((c_i, &a), &b)| {
            *c_i = a * b;
        });

    domain.ifft_in_place(&mut a);
    domain.ifft_in_place(&mut b);
    domain.ifft_in_place(&mut c);

    let root_of_unity = {
        let domain_size_double = 2 * domain_size;
        let domain_double = D::new(domain_size_double)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        domain_double.element(1)
    };

    D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
    D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());
    D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());

    domain.fft_in_place(&mut a);
    domain.fft_in_place(&mut b);
    domain.fft_in_place(&mut c);

    Ok(QAP {
        num_inputs,
        num_constraints,
        a,
        b,
        c,
        domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::Groth16;
    use ark_poly::Radix2EvaluationDomain;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    #[test]
    fn creates_qap() {
        let cfg = CircomConfig::<Bn254>::new(
            "../fixtures/sha256/sha256.wasm",
            "../fixtures/sha256/sha256.r1cs",
        )
        .unwrap();
        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("a", 3);
        builder.push_input("b", 11);

        let circom = builder.build().unwrap();
        let full_assignment = circom.witness.clone().unwrap();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circom.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        let matrices = cs.to_matrices().unwrap();

        let qap =
            qap::<Fr, Radix2EvaluationDomain<_>>(&matrices, &full_assignment);
        eprintln!("{:?}", qap);
    }

    #[test]
    fn setup() {
        let cfg = CircomConfig::<Bn254>::new(
            "../fixtures/sha256/sha256_js/sha256.wasm",
            "../fixtures/sha256/sha256.r1cs",
        )
        .unwrap();
        let builder = CircomBuilder::new(cfg);
        let circom = builder.setup();
        let rng = &mut ark_std::rand::thread_rng();
        let (pk, vk) =
            Groth16::<Bn254, CircomReduction>::circuit_specific_setup(
                circom, rng,
            )
            .unwrap();

        // Do something with keys.
    }
}
