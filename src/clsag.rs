//! CLSAG signature generation and verification.

#[macro_use]
mod macros;
mod sign;
mod verify;

pub use sign::sign;
pub use verify::verify;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use hash_edwards_to_edwards::hash_point_to_point;
use std::convert::TryInto;
use std::fmt::Debug;

const RING_SIZE: usize = 11;

#[allow(non_snake_case)]
// L_i = s_i * G + c_p * pk_i + c_c * (commitment_i - pseudoutcommitment)
fn compute_L(
    h_prev: Scalar,
    mu_P: Scalar,
    mu_C: Scalar,
    s_i: Scalar,
    pk_i: EdwardsPoint,
    adjusted_commitment_i: EdwardsPoint,
) -> EdwardsPoint {
    let c_p = h_prev * mu_P;
    let c_c = h_prev * mu_C;

    (s_i * ED25519_BASEPOINT_POINT) + (c_p * pk_i) + c_c * adjusted_commitment_i
}

#[allow(non_snake_case)]
// R_i = s_i * H_p_pk_i + c_p * I + c_c * (z * hash_to_point(signing pk))
fn compute_R(
    h_prev: Scalar,
    mu_P: Scalar,
    mu_C: Scalar,
    s_i: Scalar,
    pk_i: EdwardsPoint,
    I: EdwardsPoint,
    D: EdwardsPoint,
) -> EdwardsPoint {
    let c_p = h_prev * mu_P;
    let c_c = h_prev * mu_C;

    let H_p_pk_i = hash_point_to_point(pk_i);

    (s_i * H_p_pk_i) + (c_p * I) + c_c * D
}

// Helper method until #![feature(array_map)] is stable.
fn array_map<T, U: Debug, const N: usize>(array: &[T; N], mapper: impl FnMut(&T) -> U) -> [U; N] {
    array
        .iter()
        .map(mapper)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::key::H;
    use rand::SeedableRng;

    #[test]
    fn sign_and_verify_at_every_index() {
        for signing_key_index in 0..RING_SIZE {
            let mut rng = rand::rngs::StdRng::from_seed([0u8; 32]);

            let msg_to_sign = b"hello world, monero is amazing!!";

            let signing_key = Scalar::random(&mut rng);
            let signing_pk = signing_key * ED25519_BASEPOINT_POINT;
            #[allow(non_snake_case)]
            let H_p_pk = hash_point_to_point(signing_pk);

            let alpha = Scalar::random(&mut rng);

            let amount_to_spend = 1000000u32;
            let fee = 10000u32;
            let output_amount = amount_to_spend - fee;

            let mut ring = random_array(|| Scalar::random(&mut rng) * ED25519_BASEPOINT_POINT);
            ring[signing_key_index] = signing_pk;

            let real_commitment_blinding = Scalar::random(&mut rng);
            let mut commitment_ring =
                random_array(|| Scalar::random(&mut rng) * ED25519_BASEPOINT_POINT);
            commitment_ring[signing_key_index] = real_commitment_blinding * ED25519_BASEPOINT_POINT
                + Scalar::from(amount_to_spend) * *H;

            let fee_key = Scalar::from(fee) * *H;

            let out_pk_blinding = Scalar::random(&mut rng);
            let out_pk =
                out_pk_blinding * ED25519_BASEPOINT_POINT + Scalar::from(output_amount) * *H;

            let pseudo_output_commitment = fee_key + out_pk;

            #[allow(non_snake_case)]
            let I = signing_key * H_p_pk;

            let signature = sign(
                msg_to_sign,
                signing_key,
                signing_key_index,
                H_p_pk,
                alpha,
                &ring,
                &commitment_ring,
                random_array(|| Scalar::random(&mut rng)),
                real_commitment_blinding - out_pk_blinding,
                pseudo_output_commitment,
                alpha * ED25519_BASEPOINT_POINT,
                alpha * H_p_pk,
                I,
            );

            assert!(
                verify(
                    &signature,
                    msg_to_sign,
                    &ring,
                    &commitment_ring,
                    I,
                    pseudo_output_commitment
                ),
                "verify failed to signing key at index {}",
                signing_key_index
            )
        }
    }

    fn random_array<T: Default + Copy, const N: usize>(rng: impl FnMut() -> T) -> [T; N] {
        let mut ring = [T::default(); N];
        ring[..].fill_with(rng);

        ring
    }
}
