use crate::clsag::{array_map, compute_L, compute_R, INV_EIGHT, RING_SIZE};
use crate::util::ringct::Clsag;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

/// Signs a message with the given signing key using Monero's implementation of the CLSAG signature algorithm.
///
/// # Design notes
///
/// This implementations is purposely defined to be pure and low-level in the way that it doesn't make any assumptions about how certain values are generated, even if it is recommended for them to be random (like `fake_responses`).
/// This serves primarily two purposes:
///
/// 1. We can very easily unit test the implementation.
/// 2. It allows for more esoteric uses of the functionality like adaptor signatures (which need to control how L & R are computed for example).
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub fn sign(
    msg: &[u8; 32],
    signing_key: Scalar,
    signing_key_index: usize,
    H_p_pk: EdwardsPoint,
    alpha: Scalar,
    ring: &[EdwardsPoint; RING_SIZE],
    commitment_ring: &[EdwardsPoint; RING_SIZE],
    fake_responses: [Scalar; RING_SIZE - 1],
    z: Scalar,
    pseudo_output_commitment: EdwardsPoint,
    L: EdwardsPoint,
    R: EdwardsPoint,
    I: EdwardsPoint,
) -> Clsag {
    let D = z * H_p_pk;
    let D_inv_8 = D * INV_EIGHT;
    let adjusted_commitment_ring =
        array_map(commitment_ring, |point| point - pseudo_output_commitment);

    let mu_P = hash_to_scalar!(
        b"CLSAG_agg_0" || ring || commitment_ring || I || D_inv_8 || pseudo_output_commitment
    );
    let mu_C = hash_to_scalar!(
        b"CLSAG_agg_1" || ring || commitment_ring || I || D_inv_8 || pseudo_output_commitment
    );
    let compute_ring_element = |L: EdwardsPoint, R: EdwardsPoint| {
        hash_to_scalar!(
            b"CLSAG_round" || ring || commitment_ring || pseudo_output_commitment || msg || L || R
        )
    };

    // What follows below is almost an exact copy of the code found in monero-project/monero.
    // If you think you can optimize this algorithm for readability, stop right there.
    // It is a reincarnation of the devil in the form of procedural programming and even though
    // it might look like there is a way of expressing this better, don't be fooled.
    // Many hours have been spent trying to improve this but all attempts either failed or
    // produced a worse result. That being said, you do have extensive unit tests at your support,
    // something we didn't enjoy whilst re-creating this algorithm.
    // If you still want to continue your endeavour, take note of the current time and add your
    // hours spent to this counter once you have given up:
    //
    // Hours spent: 5
    //
    // You have been warned.

    let h_signing_index = compute_ring_element(L, R);

    let mut h_prev = h_signing_index;
    let mut i = (signing_key_index + 1) % RING_SIZE;
    let mut h_0 = Scalar::zero();

    if i == 0 {
        h_0 = h_signing_index
    }

    let mut responses = [Scalar::zero(); 11];

    while i != signing_key_index {
        let s_i = fake_responses[i % 10];
        responses[i] = s_i;

        let L_i = compute_L(
            h_prev,
            mu_P,
            mu_C,
            s_i,
            ring[i],
            adjusted_commitment_ring[i],
        );
        let R_i = compute_R(h_prev, mu_P, mu_C, s_i, ring[i], I, D);

        let h = compute_ring_element(L_i, R_i);

        i = (i + 1) % RING_SIZE;
        if i == 0 {
            h_0 = h
        }

        h_prev = h
    }

    responses[signing_key_index] = alpha - h_prev * ((mu_P * signing_key) + (mu_C * z));

    Clsag {
        s: responses.iter().map(|s| s.to_bytes().into()).collect(),
        c1: h_0.to_bytes().into(),
        D: D_inv_8.compress().to_bytes().into(),
    }
}
