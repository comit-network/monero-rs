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

//! # Rust Monero Library
//!
//! This is a library for which supports subsets of the Monero protocol and type primitives. It is
//! designed for Rust programs built to work with the Monero ecosystem.
//!
//! The library currently focuses on manipulating types such as addresses, transactions, blocks and
//! public keys, but do **NOT** implementat transaction signing. There is no immediate plan to add
//! such support.
//!
//! ## Default features
//!
//! The default feature `full` enables the `std` and `rand` features for the `fixed-hash`
//! dependency.
//!
//! It is worth noting that `std` is widely used all over the library and no `no_std` support is
//! planned at the moment.
//!
//! ## `strict_encoding` Support
//!
//! The `strict_encoding_support` feature enables `StrictEncode` and `StrictDecode` trait
//! implementation for a few types that implements [`consensus::Encodable`] and
//! [`consensus::Decodable`].
//!
//! `strict_encoding` is a wrapper that allows multiple consensus encoding to work under the same
//! interface, i.e. `StrictEncode` and `StrictDecode`.
//!
//! ## `serde` Support
//!
//! The `serde_support` feature enables implementation of `serde` on serializable types.
//!
//! ## Caution
//!
//! The Software is provided “as is”, without warranty of any kind, express or implied, including
//! but not limited to the warranties of merchantability, fitness for a particular purpose and
//! noninfringement. In no event shall the authors or copyright holders be liable for any claim,
//! damages or other liability, whether in an action of contract, tort or otherwise, arising from,
//! out of or in connection with the software or the use or other dealings in the Software.
//!

#![cfg_attr(docsrs, feature(doc_cfg))]
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(unused_mut)]
#![deny(missing_docs)]

#[macro_use]
mod internal_macros;
#[macro_use]
pub mod consensus;
pub mod blockdata;
mod bulletproof;
pub mod cryptonote;
pub mod network;
pub mod util;

pub use blockdata::block::Block;
pub use blockdata::block::BlockHeader;
pub use blockdata::transaction::OwnedTxOut;
pub use blockdata::transaction::Transaction;
pub use blockdata::transaction::TransactionPrefix;
pub use blockdata::transaction::TxIn;
pub use blockdata::transaction::TxOut;
pub use consensus::encode::VarInt;
pub use cryptonote::hash::Hash;
pub use bulletproof::{make_bulletproof, verify_bulletproof};
pub use network::Network;
pub use util::address::Address;
pub use util::address::AddressType;
pub use util::amount::Amount;
pub use util::amount::Denomination;
pub use util::amount::SignedAmount;
pub use util::key::KeyPair;
pub use util::key::PrivateKey;
pub use util::key::PublicKey;
pub use util::key::ViewPair;
pub use util::Error;
