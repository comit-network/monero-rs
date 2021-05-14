use crate::clsag::{array_map, compute_L, compute_R, EIGHT, RING_SIZE};
use crate::util::ringct::Clsag;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;

/// Verifies a CLSAG signature in accordance with Monero's implementation.
#[allow(non_snake_case)]
#[must_use]
pub fn verify(
    signature: &Clsag,
    msg: &[u8; 32],
    ring: &[EdwardsPoint; RING_SIZE],
    commitment_ring: &[EdwardsPoint; RING_SIZE],
    I: EdwardsPoint,
    pseudo_output_commitment: EdwardsPoint,
) -> bool {
    let D_inv_8 = match CompressedEdwardsY(signature.D.key).decompress() {
        Some(D_inv_8) => D_inv_8,
        None => return false,
    };
    let h_0 = Scalar::from_bytes_mod_order(signature.c1.key);
    let responses = signature
        .s
        .iter()
        .copied()
        .map(|s| Scalar::from_bytes_mod_order(s.key));
    let D = D_inv_8 * EIGHT;

    let mu_P = hash_to_scalar!(
        b"CLSAG_agg_0" || ring || commitment_ring || I || D_inv_8 || pseudo_output_commitment
    );
    let mu_C = hash_to_scalar!(
        b"CLSAG_agg_1" || ring || commitment_ring || I || D_inv_8 || pseudo_output_commitment
    );

    let adjusted_commitment_ring =
        array_map(commitment_ring, |point| point - pseudo_output_commitment);

    let h_0_computed = itertools::izip!(responses, ring.iter(), adjusted_commitment_ring.iter())
        .fold(h_0, |h, (s_i, pk_i, adjusted_commitment_i)| {
            let L_i = compute_L(h, mu_P, mu_C, s_i, *pk_i, *adjusted_commitment_i);
            let R_i = compute_R(h, mu_P, mu_C, s_i, *pk_i, I, D);

            hash_to_scalar!(
                b"CLSAG_round"
                    || ring
                    || commitment_ring
                    || pseudo_output_commitment
                    || msg
                    || L_i
                    || R_i
            )
        });

    h_0_computed == h_0
}
