// Adapted from https://github.com/Alexhuszagh/rust-lexical.

//! Big integer type definition.

use super::math::*;

/// Storage for a big integer type.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Bigint {
    /// Internal storage for the Bigint, in little-endian order.
    pub(crate) data: LimbVec,
}

impl Default for Bigint {
    fn default() -> Self {
        Bigint {
            data: LimbVec::with_capacity(20),
        }
    }
}

impl Math for Bigint {
    #[inline]
    fn data(&self) -> &LimbVec {
        &self.data
    }

    #[inline]
    fn data_mut(&mut self) -> &mut LimbVec {
        &mut self.data
    }
}
