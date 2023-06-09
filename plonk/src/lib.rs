use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

pub mod dplonk;
pub mod dpoly_commit;
pub mod localplonk;
pub mod poly_commit;

#[derive(Debug, Clone, PartialEq)]
pub struct PlonkDomain<F>
where
    F: FftField,
{
    pub n_gates: usize,
    pub gates: Radix2EvaluationDomain<F>,
    pub gates8: Radix2EvaluationDomain<F>,
}

impl<F: FftField> PlonkDomain<F> {
    #[allow(unused)]
    pub fn new(n_gates: usize) -> Self {
        let gates = Radix2EvaluationDomain::<F>::new(n_gates).unwrap();
        let gates8 = Radix2EvaluationDomain::<F>::new(8 * n_gates).unwrap();

        debug_assert_eq!(gates.size(), n_gates);
        debug_assert_eq!(gates8.size(), 8 * n_gates);

        PlonkDomain {
            n_gates,
            gates,
            gates8,
        }
    }
}
