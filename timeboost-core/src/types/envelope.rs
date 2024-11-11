use std::ops::Deref;

use committable::Committable;
use serde::{Deserialize, Serialize};
use std::{hash::Hash, marker::PhantomData};
use tracing::warn;

use crate::types::committee::StaticCommittee;
use crate::types::signed::Signed;

use super::Keypair;

/// Marker type to denote envelopes whose signature has not been validated.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Unchecked {}

/// Marker type to denote envelopes whose signature has been validated.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Validated {}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Envelope<D: Committable, S> {
    signed: Signed<D>,
    _marker: PhantomData<fn(S)>,
}

impl<D: Committable> Envelope<D, Validated> {
    /// Create a (validated) envelope by signing data with a private key.
    pub fn signed(d: D, keypair: &Keypair) -> Self {
        Self {
            signed: Signed::new(d, keypair),
            _marker: PhantomData,
        }
    }

    /// A validated envelope can be cast to envelopes of other types.
    ///
    /// E.g. Validated -> Unchecked
    pub fn cast<S>(self) -> Envelope<D, S> {
        Envelope {
            signed: self.signed,
            _marker: PhantomData,
        }
    }

    pub fn into_signed(self) -> Signed<D> {
        self.signed
    }

    pub fn into_data(self) -> D {
        self.signed.into_data()
    }
}

impl<D: Committable, S> Envelope<D, S> {
    /// Is the signature of this envelope valid?
    pub fn is_valid(&self, membership: &StaticCommittee) -> bool {
        self.signed.is_valid(membership)
    }

    /// Transition from an unchecked envelope to a validated one.
    ///
    /// This checks that the signature of the envelope is valid and represents
    /// the only way to get a validated envelope from an unchecked one.
    pub fn validated(self, membership: &StaticCommittee) -> Option<Envelope<D, Validated>> {
        if !self.is_valid(membership) {
            warn!(from = %self.signing_key(), commit = %self.commitment(), "invalid envelope");
            return None;
        }
        Some(Envelope {
            signed: self.signed,
            _marker: PhantomData,
        })
    }
}

impl<D: Committable, S> Deref for Envelope<D, S> {
    type Target = Signed<D>;

    fn deref(&self) -> &Self::Target {
        &self.signed
    }
}
