use std::{hash::Hash, marker::PhantomData, ops::Deref};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{Committee, Keypair, Signed, Versioned};

/// Marker type to denote envelopes whose signature has not been validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Unchecked {}

/// Marker type to denote envelopes whose signature has been validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize)]
pub enum Validated {}

/// An envelope contains data, its signed commitment hash and the signing key.
///
/// Envelopes are either unchecked or validated. If validated it means that their
/// signature has been checked at least once. By construction it is impossible to
/// create a validated envelope without either creating or verifying the signature.
///
///```compile_fail
/// use multisig::{Envelope, Signature, Validated};
///
/// let _: Envelope<Signature, Validated> =
///     bincode::serde::decode_from_slice(&[], bincode::config::standard()).unwrap().0;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(bound(deserialize = "D: Deserialize<'de>, S: Deserialize<'de>"))]
pub struct Envelope<D: Committable, S> {
    signed: Signed<D>,
    #[serde(skip)]
    _marker: PhantomData<fn(S)>,
}

impl<D: Committable> Envelope<D, Validated> {
    /// Create a (validated) envelope by signing data with a private key.
    pub fn signed(d: Versioned<D>, keypair: &Keypair, deterministic: bool) -> Self {
        Self {
            signed: Signed::new(d, keypair, deterministic),
            _marker: PhantomData,
        }
    }
}

impl<D: Committable, S> Envelope<D, S> {
    /// Transition from an unchecked envelope to a validated one.
    ///
    /// This checks that the signature of the envelope is valid and represents
    /// the only way to get a validated envelope from an unchecked one.
    pub fn validated(self, membership: &Committee) -> Option<Envelope<D, Validated>> {
        if !self.is_valid(membership) {
            return None;
        }
        Some(Envelope {
            signed: self.signed,
            _marker: PhantomData,
        })
    }

    pub fn into_signed(self) -> Signed<D> {
        self.signed
    }

    pub fn into_data(self) -> Versioned<D> {
        self.signed.into_data()
    }
}

impl<D: Committable, S> Deref for Envelope<D, S> {
    type Target = Signed<D>;

    fn deref(&self) -> &Self::Target {
        &self.signed
    }
}

impl<D: Committable, S> Committable for Envelope<D, S> {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Envelope")
            .field("signed", self.signed.commit())
            .finalize()
    }
}
