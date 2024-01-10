use ark_ff::FftField;
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};

pub mod ext_wit;
pub mod pre_processing;
// pub mod prove;
pub mod proving_key;
pub mod qap;

#[derive(Debug, Clone, PartialEq)]
pub struct ConstraintDomain<F>
where
    F: FftField,
{
    pub m: usize,                               // Constraint size
    pub constraint: Radix2EvaluationDomain<F>,  // Constraint domain
    pub constraint2: Radix2EvaluationDomain<F>, // Constraint2 domain
}

impl<F: FftField> ConstraintDomain<F> {
    #[allow(unused)]
    pub fn new(m: usize) -> Self {
        let constraint = Radix2EvaluationDomain::<F>::new(m).unwrap();
        let constraint2 = Radix2EvaluationDomain::<F>::new(2 * m).unwrap();

        debug_assert_eq!(constraint.size(), m);
        debug_assert_eq!(constraint2.size(), 2 * m);

        ConstraintDomain {
            m,
            constraint,
            constraint2,
        }
    }
}
