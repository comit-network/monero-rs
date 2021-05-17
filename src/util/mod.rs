// Rust Monero Library
// Written in 2019 by
//   h4sh3d <h4sh3d@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//

//! Utility functions to manipulate addresses, amounts, keys, or ringct data types.
//!
//! Shared functions needed in different part of the library or utility types for external
//! integrations.
//!

pub mod address;
pub mod amount;
pub mod key;
pub mod ringct;

use super::network;
use crate::blockdata::transaction;

use curve25519_dalek::scalar::Scalar;
use thiserror::Error;

/// A general error code, other errors should implement conversions to/from this if appropriate.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Monero network error.
    #[error("Network error: {0}")]
    Network(#[from] network::Error),
    /// Monero address error.
    #[error("Address error: {0}")]
    Address(#[from] address::Error),
    /// Monero key error.
    #[error("Key error: {0}")]
    Key(#[from] key::Error),
    /// Monero RingCt error.
    #[error("RingCt error: {0}")]
    RingCt(#[from] ringct::Error),
    /// Monero transaction error.
    #[error("Transaction error: {0}")]
    Transaction(#[from] transaction::Error),
    /// Monero amount parsing error.
    #[error("Amount parsing error: {0}")]
    AmountParsing(#[from] amount::ParsingError),
}

/// Defines the constant 1/8.
///
/// Monero likes to multiply things by 8 as part of CLSAG, Bulletproof and key derivation.
/// As such, we also sometimes need to multiply by its inverse to undo this operation.
///
/// We define the constant here once instead of littering it across the codebase.
pub const INV_EIGHT: Scalar = Scalar::from_bits([
    121, 47, 220, 226, 41, 229, 6, 97, 208, 218, 28, 125, 179, 157, 211, 7, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 6,
]);

/// Defines the constant 8.
///
/// Monero likes to multiply things by 8 as part of CLSAG, Bulletproof and key derivation.
/// We define the constant here once instead of littering it across the codebase.
pub const EIGHT: Scalar = Scalar::from_bits([
    8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_is_inv_eight() {
        let inv_eight = Scalar::from(8u8).invert();

        assert_eq!(inv_eight, INV_EIGHT);
    }

    #[test]
    fn const_is_eight() {
        let eight = Scalar::from(8u8);

        assert_eq!(eight, EIGHT);
    }
}
