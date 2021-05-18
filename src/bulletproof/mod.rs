//! Bulletproof
//!
//! Copied from https://github.com/dalek-cryptography/bulletproofs and
//! modified to mimic Monero's `bulletproof_PROVE` and `bulletproof_VERIFY` algorithms.

#![allow(non_snake_case)]

use core::iter;
use std::convert::TryFrom;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use keccak_hash::keccak_256;
use rand::{CryptoRng, RngCore};

use inner_product_proof::InnerProductProof;

use crate::util::{EIGHT, INV_EIGHT};
pub use generators::{BulletproofGens, PedersenGens};

mod dealer;
mod generators;
mod inner_product_proof;
mod messages;
mod party;
mod util;

/// Generate `Bulletproof` for the provided `amounts`.
///
/// Also returns the amount commitments, together with their
/// corresponding random blindings.
pub fn make_bulletproof<T>(
    rng: &mut T,
    amounts: &[u64],
    blindings: &[Scalar],
) -> Result<(crate::util::ringct::Bulletproof, Vec<EdwardsPoint>), ProofError>
where
    T: RngCore + CryptoRng,
{
    let amount_bits = 64;
    let n_commitments = amounts.len();

    let bp_gens = BulletproofGens::new(amount_bits, n_commitments);
    let pc_gens = PedersenGens::default();

    let (proof, commitments) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        amounts,
        &blindings,
        amount_bits,
        rng,
    )?;

    Ok((
        proof.into(),
        commitments
            .into_iter()
            .map(|c| c * Scalar::from(8u8))
            .collect(),
    ))
}

/// Verify that the `proof` is valid for the provided commitments.
pub fn verify_bulletproof<T>(
    rng: &mut T,
    proof: crate::util::ringct::Bulletproof,
    commitments: Vec<EdwardsPoint>,
) -> Result<(), ProofError>
where
    T: RngCore + CryptoRng,
{
    let amount_bits = 64;
    let n_commitments = commitments.len();
    let commitments = commitments
        .into_iter()
        .map(|c| c * INV_EIGHT)
        .collect::<Vec<_>>();

    let bp_gens = BulletproofGens::new(amount_bits, n_commitments);
    let pc_gens = PedersenGens::default();

    let proof = RangeProof::try_from(proof).map_err(|_| ProofError::FormatError)?;
    proof.verify_multiple_with_rng(&bp_gens, &pc_gens, &commitments, amount_bits, rng)
}

/// The `RangeProof` struct represents a proof that one or more values
/// are in a range.
///
/// The `RangeProof` struct contains functions for creating and
/// verifying aggregated range proofs.  The single-value case is
/// implemented as a special case of aggregated range proofs.
///
/// The bitsize of the range, as well as the list of commitments to
/// the values, are not included in the proof, and must be known to
/// the verifier.
///
/// This implementation requires that both the bitsize `n` and the
/// aggregation size `m` be powers of two, so that `n = 8, 16, 32, 64`
/// and `m = 1, 2, 4, 8, 16, ...`.  Note that the aggregation size is
/// not given as an explicit parameter, but is determined by the
/// number of values or commitments passed to the prover or verifier.
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Commitment to the bits of the value
    A: EdwardsPoint,
    /// Commitment to the blinding factors
    S: EdwardsPoint,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    T_1: EdwardsPoint,
    /// Commitment to the \\(t_2\\) coefficient of \\( t(x) \\)
    T_2: EdwardsPoint,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    t_x: Scalar,
    /// Blinding factor for the synthetic commitment to \\(t(x)\\)
    t_x_blinding: Scalar,
    /// Blinding factor for the synthetic commitment to the inner-product arguments
    e_blinding: Scalar,
    /// Proof data for the inner-product argument.
    ipp_proof: InnerProductProof,
}

impl RangeProof {
    /// Create a rangeproof for a given pair of value `v` and blinding
    /// scalar `v_blinding`.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::prove_multiple`].
    pub fn prove_single_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        v: u64,
        v_blinding: &Scalar,
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof, EdwardsPoint), ProofError> {
        let (p, Vs) =
            RangeProof::prove_multiple_with_rng(bp_gens, pc_gens, &[v], &[*v_blinding], n, rng)?;
        Ok((p, Vs[0]))
    }

    /// Create a rangeproof for a given pair of value `v` and blinding
    /// scalar `v_blinding`.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::prove_single_with_rng`], passing in a threadsafe
    /// RNG.
    pub fn prove_single(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        v: u64,
        v_blinding: &Scalar,
        n: usize,
    ) -> Result<(RangeProof, EdwardsPoint), ProofError> {
        RangeProof::prove_single_with_rng(
            bp_gens,
            pc_gens,
            v,
            v_blinding,
            n,
            &mut rand::thread_rng(),
        )
    }

    /// Create a rangeproof for a set of values.
    pub fn prove_multiple_with_rng<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        values: &[u64],
        blindings: &[Scalar],
        n: usize,
        rng: &mut T,
    ) -> Result<(RangeProof, Vec<EdwardsPoint>), ProofError> {
        use self::dealer::*;
        use self::party::*;

        if values.len() != blindings.len() {
            return Err(ProofError::WrongNumBlindingFactors);
        }

        let dealer = Dealer::create(bp_gens, pc_gens, n, values.len())?;

        let parties: Vec<_> = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, &v_blinding)| Party::create(bp_gens, pc_gens, v, v_blinding, n))
            .collect::<Result<Vec<_>, _>>()?;

        let (parties, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(j, p)| {
                p.assign_position_with_rng(j, rng)
                    .expect("We already checked the parameters, so this should never happen")
            })
            .unzip();

        let value_commitments: Vec<_> = bit_commitments.iter().map(|c| c.V_j).collect();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(bit_commitments)?;

        let (parties, poly_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let (dealer, poly_challenge) = dealer.receive_poly_commitments(poly_commitments)?;

        let proof_shares: Vec<_> = parties
            .into_iter()
            .map(|p| p.apply_challenge(&poly_challenge))
            .collect::<Result<Vec<_>, _>>()?;

        let proof = dealer.receive_trusted_shares(&proof_shares)?;

        Ok((proof, value_commitments))
    }

    /// Create a rangeproof for a set of values.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::prove_multiple_with_rng`], passing in a
    /// threadsafe RNG.
    pub fn prove_multiple(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        values: &[u64],
        blindings: &[Scalar],
        n: usize,
    ) -> Result<(RangeProof, Vec<EdwardsPoint>), ProofError> {
        RangeProof::prove_multiple_with_rng(
            bp_gens,
            pc_gens,
            values,
            blindings,
            n,
            &mut rand::thread_rng(),
        )
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around `verify_multiple` for the
    /// `m=1` case.
    pub fn verify_single_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        V: &EdwardsPoint,
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(bp_gens, pc_gens, &[*V], n, rng)
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::verify_single_with_rng`], passing in a
    /// threadsafe RNG.
    pub fn verify_single(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        V: &EdwardsPoint,
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_single_with_rng(bp_gens, pc_gens, V, n, &mut rand::thread_rng())
    }

    /// Verifies an aggregated rangeproof for the given value
    /// commitments.
    #[allow(clippy::many_single_char_names)]
    pub fn verify_multiple_with_rng<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        value_commitments: &[EdwardsPoint],
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
        let m = value_commitments.len();

        // First, replay the "interactive" protocol using the proof
        // data to recompute all challenges.
        if !(n == 8 || n == 16 || n == 32 || n == 64) {
            return Err(ProofError::InvalidBitsize);
        }
        if bp_gens.gens_capacity < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if bp_gens.party_capacity < m {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        let mut input = vec![];
        for commitment in value_commitments.iter() {
            input.extend_from_slice(commitment.compress().as_bytes());
        }
        let mut hash_commitments = [0u8; 32];
        keccak_256(&input, &mut hash_commitments);
        let hash_commitments = Scalar::from_bytes_mod_order(hash_commitments);

        let mut input = hash_commitments.as_bytes().to_vec();
        input.extend_from_slice(self.A.compress().as_bytes());
        input.extend_from_slice(self.S.compress().as_bytes());

        let mut y = [0u8; 32];
        keccak_256(&input, &mut y);
        let y = Scalar::from_bytes_mod_order(y);

        if y == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        let mut z = [0u8; 32];
        keccak_256(y.as_bytes(), &mut z);

        let z = Scalar::from_bytes_mod_order(z);

        if z == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        let zz = z * z;
        let minus_z = -z;

        let mut input = z.as_bytes().to_vec();
        input.extend_from_slice(z.as_bytes());
        input.extend_from_slice(self.T_1.compress().as_bytes());
        input.extend_from_slice(self.T_2.compress().as_bytes());

        let mut x = [0u8; 32];
        keccak_256(&input, &mut x);
        let x = Scalar::from_bytes_mod_order(x);

        if x == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        let mut input = x.as_bytes().to_vec();
        input.extend_from_slice(x.as_bytes());
        input.extend_from_slice(self.t_x_blinding.as_bytes());
        input.extend_from_slice(self.e_blinding.as_bytes());
        input.extend_from_slice(self.t_x.as_bytes());

        let mut w = [0u8; 32];
        keccak_256(&input, &mut w);
        let w = Scalar::from_bytes_mod_order(w);

        if w == Scalar::zero() {
            return Err(ProofError::VerificationError);
        }

        // Challenge value for batching statements to be verified
        let c = Scalar::random(rng);

        let (x_sq, x_inv_sq, s) = self.ipp_proof.verification_scalars(n * m, w)?;
        let s_inv = s.iter().rev();

        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;

        // Construct concat_z_and_2, an iterator of the values of
        // z^0 * \vec(2)^n || z^1 * \vec(2)^n || ... || z^(m-1) * \vec(2)^n
        let powers_of_2: Vec<Scalar> = util::exp_iter(Scalar::from(2u64)).take(n).collect();
        let concat_z_and_2: Vec<Scalar> = util::exp_iter(z)
            .take(m)
            .flat_map(|exp_z| powers_of_2.iter().map(move |exp_2| exp_2 * exp_z))
            .collect();

        let g = s.iter().map(|s_i| minus_z - a * s_i);
        let h = s_inv
            .zip(util::exp_iter(y.invert()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2 - b * s_i_inv));

        let value_commitment_scalars = util::exp_iter(z).take(m).map(|z_exp| c * zz * z_exp);
        let basepoint_scalar = w * (self.t_x - a * b) + c * (delta(n, m, &y, &z) - self.t_x);

        let mega_check = EdwardsPoint::optional_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(x))
                .chain(iter::once(c * x))
                .chain(iter::once(c * x * x))
                .chain(x_sq.iter().cloned())
                .chain(x_inv_sq.iter().cloned())
                .chain(iter::once(-self.e_blinding - c * self.t_x_blinding))
                .chain(iter::once(basepoint_scalar))
                .chain(g)
                .chain(h)
                .chain(value_commitment_scalars),
            iter::once(EIGHT * self.A)
                .chain(iter::once(EIGHT * self.S))
                .chain(iter::once(EIGHT * self.T_1))
                .chain(iter::once(EIGHT * self.T_2))
                .chain(self.ipp_proof.L_vec.iter().map(|L| EIGHT * L))
                .chain(self.ipp_proof.R_vec.iter().map(|R| EIGHT * R))
                .chain(iter::once(pc_gens.B_blinding))
                .chain(iter::once(pc_gens.B))
                .chain(bp_gens.G(n, m).copied())
                .chain(bp_gens.H(n, m).copied())
                .chain(value_commitments.iter().map(|V| EIGHT * V))
                .map(Some),
        )
        .ok_or(ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Verifies an aggregated rangeproof for the given value
    /// commitments.
    ///
    /// This is a convenience wrapper around
    /// [`RangeProof::verify_multiple_with_rng`], passing in a
    /// threadsafe RNG.
    pub fn verify_multiple(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        value_commitments: &[EdwardsPoint],
        n: usize,
    ) -> Result<(), ProofError> {
        self.verify_multiple_with_rng(
            bp_gens,
            pc_gens,
            value_commitments,
            n,
            &mut rand::thread_rng(),
        )
    }
}

/// Compute
/// \\[
/// \delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle
/// \\]
fn delta(n: usize, m: usize, y: &Scalar, z: &Scalar) -> Scalar {
    let sum_y = util::sum_of_powers(y, n * m);
    let sum_2 = util::sum_of_powers(&Scalar::from(2u64), n);
    let sum_z = util::sum_of_powers(z, m);

    (z - z * z) * sum_y - z * z * z * sum_2 * sum_z
}

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProofError {
    /// This error occurs when a proof failed to verify.
    #[error("Proof verification failed.")]
    VerificationError,
    /// This error occurs when the proof encoding is malformed.
    #[error("Proof data could not be parsed.")]
    FormatError,
    /// This error occurs during proving if the number of blinding
    /// factors does not match the number of values.
    #[error("Wrong number of blinding factors supplied.")]
    WrongNumBlindingFactors,
    /// This error occurs when attempting to create a proof with
    /// bitsize other than \\(8\\), \\(16\\), \\(32\\), or \\(64\\).
    #[error("Invalid bitsize, must have n = 8,16,32,64.")]
    InvalidBitsize,
    /// This error occurs when attempting to create an aggregated
    /// proof with non-power-of-two aggregation size.
    #[error("Invalid aggregation size, m must be a power of 2.")]
    InvalidAggregation,
    /// This error occurs when there are insufficient generators for the proof.
    #[error("Invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,
    /// This error results from an internal error during proving.
    ///
    /// The single-party prover is implemented by performing
    /// multiparty computation with ourselves.  However, because the
    /// MPC protocol is not exposed by the single-party API, we
    /// consider its errors to be internal errors.
    #[error("Internal error during proof creation: {0}")]
    ProvingError(MpcError),
}

impl From<MpcError> for ProofError {
    fn from(e: MpcError) -> ProofError {
        match e {
            MpcError::InvalidBitsize => ProofError::InvalidBitsize,
            MpcError::InvalidAggregation => ProofError::InvalidAggregation,
            MpcError::InvalidGeneratorsLength => ProofError::InvalidGeneratorsLength,
            _ => ProofError::ProvingError(e),
        }
    }
}

/// Represents an error during the multiparty computation protocol for
/// proof aggregation.
///
/// This is a separate type from the `ProofError` to allow a layered
/// API: although the MPC protocol is used internally for single-party
/// proving, its API should not expose the complexity of the MPC
/// protocol.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MpcError {
    /// This error occurs when the dealer gives a zero challenge,
    /// which would annihilate the blinding factors.
    #[error("Dealer gave a malicious challenge value.")]
    MaliciousDealer,
    /// This error occurs when attempting to create a proof with
    /// bitsize other than \\(8\\), \\(16\\), \\(32\\), or \\(64\\).
    #[error("Invalid bitsize, must have n = 8,16,32,64")]
    InvalidBitsize,
    /// This error occurs when attempting to create an aggregated
    /// proof with non-power-of-two aggregation size.
    #[error("Invalid aggregation size, m must be a power of 2")]
    InvalidAggregation,
    /// This error occurs when there are insufficient generators for the proof.
    #[error("Invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,
    /// This error occurs when the dealer is given the wrong number of
    /// value commitments.
    #[error("Wrong number of value commitments")]
    WrongNumBitCommitments,
    /// This error occurs when the dealer is given the wrong number of
    /// polynomial commitments.
    #[error("Wrong number of value commitments")]
    WrongNumPolyCommitments,
    /// This error occurs when the dealer is given the wrong number of
    /// proof shares.
    #[error("Wrong number of proof shares")]
    WrongNumProofShares,
    /// This error occurs when one or more parties submit malformed
    /// proof shares.
    #[error("Malformed proof shares from parties {bad_shares:?}")]
    MalformedProofShares {
        /// A vector with the indexes of the parties whose shares were malformed.
        bad_shares: Vec<usize>,
    },
}

impl From<RangeProof> for crate::util::ringct::Bulletproof {
    fn from(from: RangeProof) -> Self {
        use crate::util::ringct::Key;

        Self {
            A: Key {
                key: from.A.compress().to_bytes(),
            },
            S: Key {
                key: from.S.compress().to_bytes(),
            },
            T1: Key {
                key: from.T_1.compress().to_bytes(),
            },
            T2: Key {
                key: from.T_2.compress().to_bytes(),
            },
            taux: Key {
                key: from.t_x_blinding.to_bytes(),
            },
            mu: Key {
                key: from.e_blinding.to_bytes(),
            },
            L: from
                .ipp_proof
                .L_vec
                .iter()
                .map(|l| Key {
                    key: l.compress().to_bytes(),
                })
                .collect(),
            R: from
                .ipp_proof
                .R_vec
                .iter()
                .map(|r| Key {
                    key: r.compress().to_bytes(),
                })
                .collect(),
            a: Key {
                key: from.ipp_proof.a.to_bytes(),
            },
            b: Key {
                key: from.ipp_proof.b.to_bytes(),
            },
            t: Key {
                key: from.t_x.to_bytes(),
            },
        }
    }
}

#[derive(Debug)]
pub enum ConversionError {
    InvalidPoint,
    NonCanonicalScalar,
}

impl TryFrom<crate::util::ringct::Bulletproof> for RangeProof {
    type Error = ConversionError;

    fn try_from(from: crate::util::ringct::Bulletproof) -> Result<Self, ConversionError> {
        Ok(Self {
            A: CompressedEdwardsY::from_slice(&from.A.key)
                .decompress()
                .ok_or(ConversionError::InvalidPoint)?,
            S: CompressedEdwardsY::from_slice(&from.S.key)
                .decompress()
                .ok_or(ConversionError::InvalidPoint)?,
            T_1: CompressedEdwardsY::from_slice(&from.T1.key)
                .decompress()
                .ok_or(ConversionError::InvalidPoint)?,
            T_2: CompressedEdwardsY::from_slice(&from.T2.key)
                .decompress()
                .ok_or(ConversionError::InvalidPoint)?,
            t_x: Scalar::from_canonical_bytes(from.t.key)
                .ok_or(ConversionError::NonCanonicalScalar)?,
            t_x_blinding: Scalar::from_canonical_bytes(from.taux.key)
                .ok_or(ConversionError::NonCanonicalScalar)?,
            e_blinding: Scalar::from_canonical_bytes(from.mu.key)
                .ok_or(ConversionError::NonCanonicalScalar)?,
            ipp_proof: InnerProductProof {
                L_vec: from
                    .L
                    .iter()
                    .map(|L| {
                        CompressedEdwardsY::from_slice(&L.key)
                            .decompress()
                            .ok_or(ConversionError::InvalidPoint)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                R_vec: from
                    .R
                    .iter()
                    .map(|R| {
                        CompressedEdwardsY::from_slice(&R.key)
                            .decompress()
                            .ok_or(ConversionError::InvalidPoint)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                a: Scalar::from_canonical_bytes(from.a.key)
                    .ok_or(ConversionError::NonCanonicalScalar)?,
                b: Scalar::from_canonical_bytes(from.b.key)
                    .ok_or(ConversionError::NonCanonicalScalar)?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn public_api() {
        let mut rng = rand::thread_rng();

        let blinding_0 = Scalar::random(&mut rng);
        let blinding_1 = Scalar::random(&mut rng);

        let (proof, commitments) =
            make_bulletproof(&mut rng, &[100u64, 2000u64], &[blinding_0, blinding_1]).unwrap();

        assert!(verify_bulletproof(&mut rng, proof, commitments).is_ok())
    }

    #[test]
    fn test_delta() {
        let mut rng = rand::thread_rng();
        let y = Scalar::random(&mut rng);
        let z = Scalar::random(&mut rng);

        // Choose n = 256 to ensure we overflow the group order during
        // the computation, to check that that's done correctly
        let n = 256;

        // code copied from previous implementation
        let z2 = z * z;
        let z3 = z2 * z;
        let mut power_g = Scalar::zero();
        let mut exp_y = Scalar::one(); // start at y^0 = 1
        let mut exp_2 = Scalar::one(); // start at 2^0 = 1
        for _ in 0..n {
            power_g += (z - z2) * exp_y - z3 * exp_2;

            exp_y *= y; // y^i -> y^(i+1)
            exp_2 = exp_2 + exp_2; // 2^i -> 2^(i+1)
        }

        assert_eq!(power_g, delta(n, 1, &y, &z),);
    }

    #[test]
    fn create_and_verify_n_32_m_1() {
        singleparty_create_and_verify_helper(32, 1);
    }

    #[test]
    fn create_and_verify_n_32_m_2() {
        singleparty_create_and_verify_helper(32, 2);
    }

    #[test]
    fn create_and_verify_n_32_m_4() {
        singleparty_create_and_verify_helper(32, 4);
    }

    #[test]
    fn create_and_verify_n_32_m_8() {
        singleparty_create_and_verify_helper(32, 8);
    }

    #[test]
    fn create_and_verify_n_64_m_1() {
        singleparty_create_and_verify_helper(64, 1);
    }

    #[test]
    fn create_and_verify_n_64_m_2() {
        singleparty_create_and_verify_helper(64, 2);
    }

    #[test]
    fn create_and_verify_n_64_m_4() {
        singleparty_create_and_verify_helper(64, 4);
    }

    #[test]
    fn create_and_verify_n_64_m_8() {
        singleparty_create_and_verify_helper(64, 8);
    }

    #[test]
    fn create_and_verify_n_64_m_16() {
        singleparty_create_and_verify_helper(64, 16);
    }

    #[test]
    fn detect_dishonest_dealer_during_aggregation() {
        use self::dealer::*;
        use self::party::*;
        use crate::bulletproof::MpcError;

        // Simulate one party
        let m = 1;
        let n = 32;

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(n, m);

        use rand::Rng;
        let mut rng = rand::thread_rng();

        let v0 = rng.gen::<u32>() as u64;
        let v0_blinding = Scalar::random(&mut rng);
        let party0 = Party::create(&bp_gens, &pc_gens, v0, v0_blinding, n).unwrap();

        let dealer = Dealer::create(&bp_gens, &pc_gens, n, m).unwrap();

        // Now do the protocol flow as normal....

        let (party0, bit_com0) = party0.assign_position(0).unwrap();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(vec![bit_com0]).unwrap();

        let (party0, poly_com0) = party0.apply_challenge(&bit_challenge);

        let (_dealer, mut poly_challenge) =
            dealer.receive_poly_commitments(vec![poly_com0]).unwrap();

        // But now simulate a malicious dealer choosing x = 0
        poly_challenge.x = Scalar::zero();

        let maybe_share0 = party0.apply_challenge(&poly_challenge);

        assert!(maybe_share0.unwrap_err() == MpcError::MaliciousDealer);
    }

    #[test]
    fn verify_monero_mainnet_bulletproof() {
        use crate::util::ringct::Bulletproof;
        use crate::util::ringct::Key;
        use hex_literal::hex;

        // data from:
        // https://xmrchain.net/tx/f34e0414a413cc7d6d4452b1a962f08be6de937eeb76fed9ca0774f5cb3b161b/1

        let proof = Bulletproof {
            A: Key {
                key: hex!("78ddbccf2e1ced3b68835600768770ebe3e219db19a35f5ebe6495ec58c763d4"),
            },
            S: Key {
                key: hex!("e61bd5f461172a14d31149207a9f473289f89dbf4c42dff5f7cbcbd87a12210e"),
            },
            T1: Key {
                key: hex!("74989471b2e26755d60128a0a54de6e8d0a3d30e9c6810f885f09be27339765f"),
            },
            T2: Key {
                key: hex!("bd0b0fb338cc8f16a3c8b05f504a34223263f6fb61865cff29f62d7731581a85"),
            },
            taux: Key {
                key: hex!("df0abd33124389ef8c32fb948b5e4b40259757b5f0ca6c7010f33c0ee625880f"),
            },
            mu: Key {
                key: hex!("5b98150bedb8ba4861246bb31f3f0cb7a0d9a915475c9be92b847be8c3236602"),
            },
            L: vec![
                Key {
                    key: hex!("0568cb5dc56fd8077435a87268931c5995367e9f45ad8527248c69c87840f17e"),
                },
                Key {
                    key: hex!("3818ef23fb0da1edb0180be8a06fe66e0c12b85955b96a329eccffeb4f0af152"),
                },
                Key {
                    key: hex!("c1f9e3d157143326e3f60101e2119c2e8528bcada27087b8248226b9ad827db5"),
                },
                Key {
                    key: hex!("46443a7d575c97658f2ffd4cdfaf53de6b39ca340e59f40d195068e4725feb89"),
                },
                Key {
                    key: hex!("b0019ac9d69c511c899ab647695bb6e5c5fff5256aa3b168ecb57b20a5ad6fa8"),
                },
                Key {
                    key: hex!("24f25935783d645279e575eac839beba4c91b04efb4fc0c8d7f4a0fa27d95fe1"),
                },
                Key {
                    key: hex!("5d8f4d63b5ce10d9ab579c30da28108c13abd54e876a0308636fdc8b0e69d059"),
                },
            ],
            R: vec![
                Key {
                    key: hex!("88f99b0bfb5a4e052b209400594c2c423a95497e3be315d9e8fbb4410bd73102"),
                },
                Key {
                    key: hex!("e2bdf54f0b3456c5816004549e76c88f004baf8a84aa3d581d7dbffde4316ec4"),
                },
                Key {
                    key: hex!("6d808eec11aa732e94040894517806aa615fadf826c9fc351f73f7c13097cc02"),
                },
                Key {
                    key: hex!("8e44c3df858a0991f5b176ae4c862f79bdb153cfb35d1e4c75c28f8493c4a3ff"),
                },
                Key {
                    key: hex!("b0334d4f506cd30173ce6398de28084fc8b687a4cfe4eca08476e8a042a8e6fd"),
                },
                Key {
                    key: hex!("cc11034e07e9c80029b4220cf15574ded93ba96a2f2bc94bd504a30abfddba5a"),
                },
                Key {
                    key: hex!("e5ede5ed6e0d603a668baa586bfa2139553ef487c1a9474fbafaa5ba5b8760d0"),
                },
            ],
            a: Key {
                key: hex!("d782e742fafc78de94aa51bfd89ec61cbf54180093b3617b694652e6a4cea005"),
            },
            b: Key {
                key: hex!("8ae6cc60d17472f9ca87ffa8932ff480bc55e00d95e60b39aa866bb94ac8f90a"),
            },
            t: Key {
                key: hex!("0f42ab37f27887291eb3f3126708e5ff4fdf4c4499bc43c61516684e9f176100"),
            },
        };

        let commitments = vec![
            CompressedEdwardsY::from_slice(
                hex::decode("5bef186a6d084a0372e3d91446f6b7ec4a900ab7b0abf7b205c5f2b2f105b32c")
                    .unwrap()
                    .as_slice(),
            )
            .decompress()
            .unwrap(),
            CompressedEdwardsY::from_slice(
                hex::decode("22d187e6a788eaeecf0fd4d31f1718e03c259f39fd120fd8ef660ddb1c36a852")
                    .unwrap()
                    .as_slice(),
            )
            .decompress()
            .unwrap(),
        ];

        verify_bulletproof(&mut thread_rng(), proof, commitments).unwrap();
    }

    /// Given a bitsize `n`, test the following:
    ///
    /// 1. Generate `m` random values and create a proof they are all in range;
    /// 2. Serialize to wire format;
    /// 3. Deserialize from wire format;
    /// 4. Verify the proof.
    fn singleparty_create_and_verify_helper(n: usize, m: usize) {
        // Split the test into two scopes, so that it's explicit what
        // data is shared between the prover and the verifier.

        // Use bincode for serialization
        //use bincode; // already present in lib.rs

        // Both prover and verifier have access to the generators and the proof
        let max_bitsize = 64;
        let max_parties = 16;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

        // Prover's scope
        let (proof, value_commitments) = {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            // 0. Create witness data
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
            let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

            // 1. Create and return the proof
            RangeProof::prove_multiple(&bp_gens, &pc_gens, &values, &blindings, n).unwrap()
        };

        // Verifier's scope
        {
            assert!(proof
                .verify_multiple(&bp_gens, &pc_gens, &value_commitments, n)
                .is_ok());
        }
    }
}
