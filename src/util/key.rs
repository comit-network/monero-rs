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

//! # Monero public and private keys.
//!
//! Support for (de)serializable and manipulation of Monero public and private keys.
//!
//! ## Parsing
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::util::key::{Error, PrivateKey, PublicKey, EdwardsPointExt, ScalarExt};
//!
//! // parse private key from hex
//! let privkey = PrivateKey::from_str("77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404")?;
//! // parse public key from hex
//! let pubkey_parsed = PublicKey::from_hex("eac2cc96e0ae684388e3185d5277e51313bff98b9ad4a12dcd9205f20d37f1a3")?;
//!
//! // or get the public key from private key
//! let pubkey = PublicKey::from_private_key(&privkey);
//!
//! assert_eq!(pubkey_parsed, pubkey);
//! # Ok::<(), Error>(())
//! ```
//!
//! ## Arithmetic
//!
//! Support for private key addition and public key addition.
//!
//! ```rust
//! use std::str::FromStr;
//! use monero::util::key::{Error, PrivateKey, PublicKey, EdwardsPointExt, ScalarExt};
//! use std::convert::TryFrom;
//! use hex_literal::hex;
//!
//! let priv1 = PrivateKey::from_str("77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404")?;
//! let priv2 = PrivateKey::from_str("8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09")?;
//! let priv_res = priv1 + priv2;
//! assert_eq!(PrivateKey::from_bits(hex!("f8f4b37bedf12a2178c0adcc2565b42a212c133861cb28cdf48abf310c3ce40d")), priv_res);
//!
//! let pub1 = PublicKey::from_private_key(&priv1);
//! let pub2 = PublicKey::from_private_key(&priv2);
//! let pub_res = pub1 + pub2;
//! assert_eq!(PublicKey::try_from(hex!("d35ad191b220a627977bb2912ea21fd59b24937f46c1d3814dbcb7943ff1f9f2")).unwrap(), pub_res);
//!
//! let pubkey = PublicKey::from_private_key(&priv_res);
//! assert_eq!(pubkey, pub_res);
//! # Ok::<(), Error>(())
//! ```
//!

use std::{fmt, io};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hex_literal::hex;
use thiserror::Error;

use crate::consensus::encode::{self, Decodable, Encodable};
use crate::cryptonote::hash;

use conquer_once::Lazy;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

/// Potential errors encountered during key decoding.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// Invalid input length.
    #[error("Invalid length")]
    InvalidLength,
    /// Not a canonical representation of an curve25519 scalar.
    #[error("Not a canonical representation of an ed25519 scalar")]
    NotCanonicalScalar,
    /// Invalid point on the curve.
    #[error("Invalid point on the curve")]
    InvalidPoint,
    /// Hex parsing error.
    #[error("Hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// A private key in Monero is simply a Scalar.
pub type PrivateKey = Scalar;

/// Extension trait for things we want to do with scalars that are not (yet) present on [`Scalar`].
pub trait ScalarExt: Sized {
    /// Construct a [`Scalar`] from a slice of bytes.
    fn from_slice(bytes: &[u8]) -> Result<Self, Error>;
    /// Construct a [`Scalar`] from a hex-encoded string.
    fn from_str(string: &str) -> Result<Self, Error>;
    /// Returns an adaptor that implements [`fmt::Display`].
    fn display_hex(&self) -> DisplayHexAdaptor<'_, Self>;
}

impl ScalarExt for Scalar {
    fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 32 {
            return Err(Error::InvalidLength);
        }

        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(bytes);

        Self::from_canonical_bytes(buffer).ok_or(Error::NotCanonicalScalar)
    }

    fn from_str(string: &str) -> Result<Self, Error> {
        let mut buffer = [0u8; 32];
        hex::decode_to_slice(string, &mut buffer)?;

        Self::from_canonical_bytes(buffer).ok_or(Error::NotCanonicalScalar)
    }

    fn display_hex(&self) -> DisplayHexAdaptor<'_, Self> {
        DisplayHexAdaptor { inner: self }
    }
}

impl Decodable for PrivateKey {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<PrivateKey, encode::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        let scalar = PrivateKey::from_canonical_bytes(bytes)
            .ok_or(encode::Error::Key(Error::NotCanonicalScalar))?;

        Ok(scalar)
    }
}

impl Encodable for PrivateKey {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.to_bytes().consensus_encode(s)
    }
}

/// A public key, a valid edward point on the curve.
pub type PublicKey = EdwardsPoint;

/// Extension trait for things we want to do with edwards points that are not (yet) present on [`EdwardsPoint`].
pub trait EdwardsPointExt: Sized {
    /// Construct an [`EdwardsPoint`] from a [`Scalar`].
    ///
    /// Essentially, this computes the "public key" of a "private key".
    fn from_private_key(key: &PrivateKey) -> Self;
    /// Returns an adaptor that implements [`fmt::Display`].
    fn display_hex(&self) -> DisplayHexAdaptor<'_, Self>;
    /// Construct an [`EdwardsPoint`] from a hex-encoded string.
    fn from_hex(string: &str) -> Result<Self, Error>;
}

impl EdwardsPointExt for EdwardsPoint {
    fn from_private_key(key: &PrivateKey) -> Self {
        key * ED25519_BASEPOINT_POINT
    }

    fn display_hex(&self) -> DisplayHexAdaptor<'_, Self> {
        DisplayHexAdaptor { inner: self }
    }

    fn from_hex(string: &str) -> Result<Self, Error> {
        let mut buffer = [0u8; 32];
        hex::decode_to_slice(string, &mut buffer)?;

        CompressedEdwardsY(buffer)
            .decompress()
            .ok_or(Error::InvalidPoint)
    }
}

/// Adaptor struct for printing type `T` as hex.
pub struct DisplayHexAdaptor<'a, T> {
    inner: &'a T,
}

impl<'a> fmt::Display for DisplayHexAdaptor<'a, EdwardsPoint> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.inner.compress().as_bytes()))
    }
}

impl<'a> fmt::Display for DisplayHexAdaptor<'a, Scalar> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.inner.as_bytes()))
    }
}

impl Decodable for PublicKey {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<PublicKey, encode::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        let compressed_edwards = CompressedEdwardsY(bytes).decompress();
        let point = compressed_edwards.ok_or(encode::Error::Key(Error::InvalidPoint))?;

        Ok(point)
    }
}

impl Encodable for PublicKey {
    fn consensus_encode<S: io::Write>(&self, s: &mut S) -> Result<usize, io::Error> {
        self.compress().to_bytes().consensus_encode(s)
    }
}

impl hash::Hashable for PublicKey {
    fn hash(&self) -> hash::Hash {
        hash::Hash::hash(&self.compress().to_bytes())
    }
}

/// Alternative generator `H` used for pedersen commitments, as defined in
/// [`rctTypes.h`](https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h#L555)
/// in the Monero codebase.
pub static H: Lazy<EdwardsPoint> = Lazy::new(|| {
    CompressedEdwardsY(hex!(
        "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
    ))
    .decompress()
    .unwrap()
});

/// Two private keys representing the view and the spend keys.
#[derive(Debug)]
pub struct KeyPair {
    /// The private view key needed to recognize owned outputs.
    pub view: PrivateKey,
    /// The private spend key needed to spend owned outputs.
    pub spend: PrivateKey,
}

/// View pair to scan transaction outputs and retreive amounts, but can't spend outputs.
#[derive(Debug)]
pub struct ViewPair {
    /// The private view key needed to recognize owned outputs and amounts.
    pub view: PrivateKey,
    /// The public spend key needed to recognize owned outputs and amounts.
    pub spend: PublicKey,
}

impl From<KeyPair> for ViewPair {
    fn from(k: KeyPair) -> ViewPair {
        let spend = PublicKey::from_private_key(&k.spend);
        ViewPair {
            view: k.view,
            spend,
        }
    }
}

impl From<&KeyPair> for ViewPair {
    fn from(k: &KeyPair) -> ViewPair {
        let spend = PublicKey::from_private_key(&k.spend);
        ViewPair {
            view: k.view,
            spend,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use std::convert::TryFrom;

    #[test]
    fn public_key_from_secret() {
        let privkey = PrivateKey::from_bits(hex!(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404"
        ));

        let public_key = PublicKey::from_private_key(&privkey);

        assert_eq!(
            PublicKey::try_from(hex!(
                "eac2cc96e0ae684388e3185d5277e51313bff98b9ad4a12dcd9205f20d37f1a3"
            ))
            .unwrap(),
            public_key
        );
    }

    #[test]
    fn parse_public_key() {
        assert!(PublicKey::try_from(hex!(
            "eac2cc96e0ae684388e3185d5277e51313bff98b9ad4a12dcd9205f20d37f1a3"
        ))
        .is_ok());
    }

    #[test]
    fn add_privkey_and_pubkey() {
        let priv1 = PrivateKey::from_bits(hex!(
            "77916d0cd56ed1920aef6ca56d8a41bac915b68e4c46a589e0956e27a7b77404"
        ));
        let priv2 = PrivateKey::from_bits(hex!(
            "8163466f1883598e6dd14027b8da727057165da91485834314f5500a65846f09"
        ));
        let priv_res = priv1 + priv2;
        assert_eq!(
            hex!("f8f4b37bedf12a2178c0adcc2565b42a212c133861cb28cdf48abf310c3ce40d"),
            priv_res.to_bytes()
        );

        let pub1 = PublicKey::from_private_key(&priv1);
        let pub2 = PublicKey::from_private_key(&priv2);
        let pub_res = pub1 + pub2;
        assert_eq!(
            PublicKey::try_from(hex!(
                "d35ad191b220a627977bb2912ea21fd59b24937f46c1d3814dbcb7943ff1f9f2"
            ))
            .unwrap(),
            pub_res
        );

        let pubkey = PublicKey::from_private_key(&priv_res);
        assert_eq!(pubkey, pub_res);
    }
}
