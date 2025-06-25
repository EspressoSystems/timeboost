//! General Lagrange interpolation in base field or in the exponent, see BonehShoup Sec 22.1.1
//!
//! For FFT evaluation domain (aka roots of unity), directly use:
//! <https://docs.rs/ark-poly/latest/ark_poly/domain/trait.EvaluationDomain.html#method.ifft>

use ark_ec::CurveGroup;
use ark_ff::{Field, batch_inversion};

/// Lagrange interpolation: given the evaluated points {x_i}, evaluations: {y_i=f(x_i)}, return f(0)
/// polynomial degree = eval_points.len() - 1
pub(crate) fn interpolate<C: CurveGroup>(
    eval_points: &[C::ScalarField],
    evals: &[C::ScalarField],
) -> anyhow::Result<C::ScalarField> {
    let n = eval_points.len();
    anyhow::ensure!(
        n == evals.len(),
        "eval_points and evals must have same length"
    );
    anyhow::ensure!(n > 0, "need at least one point");

    let lagrange_coeffs = lagrange_coeffs_at_zero(eval_points);
    let result = lagrange_coeffs
        .iter()
        .zip(evals)
        .map(|(l, y)| *l * *y)
        .sum();
    Ok(result)
}

/// Given evaluated points {x_i}, evaluations in the exponents: {g^y_i}, returns g^f(0)
/// polynomial degree = eval_points.len() - 1
/// Corollary 22.2 of BonehShoup book
pub(crate) fn interpolate_in_exponent<C: CurveGroup>(
    eval_points: &[C::ScalarField],
    evals_in_exp: &[C::Affine],
) -> anyhow::Result<C> {
    let n = eval_points.len();
    anyhow::ensure!(
        n == evals_in_exp.len(),
        "eval_points and evals_in_exp must have same length"
    );
    anyhow::ensure!(n > 0, "need at least one point");

    let lagrange_coeffs = lagrange_coeffs_at_zero(eval_points);
    C::msm(evals_in_exp, &lagrange_coeffs)
        .map_err(|e| anyhow::anyhow!("Interpolate in exponent failed: {:?}", e))
}

/// Compute barycentric Lagrange coefficients at 0 for given eval points
fn lagrange_coeffs_at_zero<F: Field>(eval_points: &[F]) -> Vec<F> {
    let n = eval_points.len();
    let mut w = vec![F::one(); n];
    for i in 0..n {
        for j in 0..n {
            if i != j {
                w[i] *= eval_points[i] - eval_points[j];
            }
        }
    }
    batch_inversion(&mut w);
    let l0 = eval_points.iter().fold(F::one(), |acc, x_i| acc * (-*x_i));
    eval_points
        .iter()
        .zip(w.iter())
        .map(|(x_i, w_i)| l0 * w_i / (-*x_i))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::{UniformRand, Zero};
    use ark_std::rand::thread_rng;

    #[test]
    fn test_interpolate_basic() {
        // f(x) = 3x^2 + 2x + 1
        let f = |x: Fr| Fr::from(3u32) * x * x + Fr::from(2u32) * x + Fr::from(1u32);
        let xs: Vec<Fr> = (1u64..=3).map(Fr::from).collect();
        let ys: Vec<Fr> = xs.iter().map(|&x| f(x)).collect();
        let interp = interpolate::<G1Projective>(&xs, &ys).unwrap();
        let f0 = f(Fr::zero());
        assert_eq!(interp, f0);
    }

    #[test]
    fn test_interpolate_random() {
        let mut rng = thread_rng();
        // Random quadratic
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = Fr::rand(&mut rng);
        let f = |x: Fr| a * x * x + b * x + c;
        let xs: Vec<Fr> = (1u64..=3).map(Fr::from).collect();
        let ys: Vec<Fr> = xs.iter().map(|&x| f(x)).collect();
        assert_eq!(interpolate::<G1Projective>(&xs, &ys).unwrap(), c);
    }

    #[test]
    fn test_interpolate_in_exponent() {
        // f(x) = 5x + 7
        let a = Fr::from(5u32);
        let b = Fr::from(7u32);
        let f = |x: Fr| a * x + b;
        let xs: Vec<Fr> = (1u64..=2).map(Fr::from).collect();
        let ys: Vec<Fr> = xs.iter().map(|&x| f(x)).collect();
        let g = G1Projective::generator();
        let gs_y: Vec<G1Affine> = ys.iter().map(|y| (g * *y).into_affine()).collect();
        let interp_exp = interpolate_in_exponent::<G1Projective>(&xs, &gs_y).unwrap();
        let expected = g * b;
        assert_eq!(interp_exp, expected);
    }
}
