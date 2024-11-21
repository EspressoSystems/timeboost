use std::{hash::Hash, marker::PhantomData};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use hotshot::types::SignatureKey;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::types::{committee::StaticCommittee, PublicKey, Signature};

use super::Keypair;

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
/// ```compile_fail
/// use timeboost_core::types::{envelope::{Envelope, Validated}, message::Timeout};
///
/// let _: Envelope<Timeout, Validated> = bincode::deserialize(&[]).unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(bound(deserialize = "D: Deserialize<'de>, S: Deserialize<'de>"))]
pub struct Envelope<D: Committable, S> {
    data: D,
    commitment: Commitment<D>,
    signature: Signature,
    signing_key: PublicKey,
    #[serde(skip)]
    _marker: PhantomData<fn(S)>,
}

impl<D: Committable> Envelope<D, Validated> {
    /// Create a (validated) envelope by signing data with a private key.
    pub fn signed(d: D, keypair: &Keypair) -> Self {
        let c = d.commit();
        let s = keypair.sign(c.as_ref());
        Self {
            data: d,
            commitment: c,
            signature: s,
            signing_key: *keypair.public_key(),
            _marker: PhantomData,
        }
    }
}

impl<D: Committable, S> Envelope<D, S> {
    /// Is the signature of this envelope valid?
    pub fn is_valid(&self, membership: &StaticCommittee) -> bool {
        membership.committee().contains(&self.signing_key)
            && self.data.commit() == self.commitment
            && self
                .signing_key
                .validate(&self.signature, self.commitment.as_ref())
    }

    /// Transition from an unchecked envelope to a validated one.
    ///
    /// This checks that the signature of the envelope is valid and represents
    /// the only way to get a validated envelope from an unchecked one.
    pub fn validated(self, membership: &StaticCommittee) -> Option<Envelope<D, Validated>> {
        if !self.is_valid(membership) {
            warn!(from = %self.signing_key, commit = %self.commitment, "invalid envelope");
            return None;
        }
        Some(Envelope {
            data: self.data,
            commitment: self.commitment,
            signature: self.signature,
            signing_key: self.signing_key,
            _marker: PhantomData,
        })
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signing_key(&self) -> &PublicKey {
        &self.signing_key
    }

    pub fn commitment(&self) -> Commitment<D> {
        self.commitment
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn into_data(self) -> D {
        self.data
    }
}

impl<D: Committable, S> Committable for Envelope<D, S> {
    fn commit(&self) -> Commitment<Self> {
        let sig = bincode::serialize(&self.signature).expect("serializing signature never fails");
        RawCommitmentBuilder::new("Envelope")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .var_size_field("signature", &sig)
            .var_size_field("signing_key", &self.signing_key.to_bytes())
            .finalize()
    }
}
