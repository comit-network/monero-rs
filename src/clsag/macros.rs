use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use std::borrow::Cow;

/// Hashes a set of elements to a Scalar.
///
/// Specifically designed to be used within the clsag module. Use with caution in other places.
macro_rules! hash_to_scalar {
    ($($e:tt) || +) => {
        {
            use crate::clsag::macros::ToHashInput as _;
            use tiny_keccak::Hasher as _;

            let mut hasher = tiny_keccak::Keccak::v256();

            $(
                let bytes_vec = $e.to_hash_input();

                for el in bytes_vec {
                    hasher.update(el.as_ref());
                }
            )+

            let mut hash = [0u8; 32];
            hasher.finalize(&mut hash);

            curve25519_dalek::scalar::Scalar::from_bytes_mod_order(hash)
        }
    };
}

/// Type alias for a single hash input element.
///
/// Monero's CLSAG implementation hashes elements as arrays of 32 bytes, even if they are shorter than that.
/// This type alias and the corresponding trait enforce this behaviour at the type-system level.
type HashInput<'a> = Cow<'a, [u8; 32]>;

pub(crate) trait ToHashInput {
    fn to_hash_input(&self) -> Vec<HashInput<'_>>;
}

impl ToHashInput for CompressedEdwardsY {
    fn to_hash_input(&self) -> Vec<HashInput<'_>> {
        vec![HashInput::Borrowed(&self.0)]
    }
}

impl ToHashInput for EdwardsPoint {
    fn to_hash_input(&self) -> Vec<HashInput<'_>> {
        vec![HashInput::Owned(self.compress().0)]
    }
}

impl ToHashInput for [u8; 32] {
    fn to_hash_input(&self) -> Vec<HashInput<'_>> {
        vec![HashInput::Borrowed(&self)]
    }
}

impl ToHashInput for [u8; 11] {
    fn to_hash_input(&self) -> Vec<HashInput<'_>> {
        let mut bytes = [0u8; 32];
        bytes[0..11].copy_from_slice(self);

        vec![HashInput::Owned(bytes)]
    }
}

impl<'a> ToHashInput for [EdwardsPoint; 11] {
    fn to_hash_input(&self) -> Vec<HashInput<'_>> {
        vec![
            HashInput::Owned(self[0].compress().0),
            HashInput::Owned(self[1].compress().0),
            HashInput::Owned(self[2].compress().0),
            HashInput::Owned(self[3].compress().0),
            HashInput::Owned(self[4].compress().0),
            HashInput::Owned(self[5].compress().0),
            HashInput::Owned(self[6].compress().0),
            HashInput::Owned(self[7].compress().0),
            HashInput::Owned(self[8].compress().0),
            HashInput::Owned(self[9].compress().0),
            HashInput::Owned(self[10].compress().0),
        ]
    }
}
