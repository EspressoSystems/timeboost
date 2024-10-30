use committable::{Commitment, Committable};
use hotshot::types::SignatureKey;
use serde::{Deserialize, Serialize};
use std::{hash::Hash, marker::PhantomData};
use tracing::warn;

use crate::types::{committee::StaticCommittee, PrivateKey, PublicKey, Signature};

/// Marker type to denote envelopes whose signature has not been validated.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Unchecked {}

/// Marker type to denote envelopes whose signature has been validated.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Validated {}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Envelope<D: Committable, S> {
    data: D,
    commitment: Commitment<D>,
    signature: Signature,
    signing_key: PublicKey,
    _marker: PhantomData<fn(S)>,
}

impl<D: Committable, S> Envelope<D, S> {
    pub fn new(data: D, signature: Signature, signing_key: PublicKey) -> Self {
        let commitment = data.commit();
        Self {
            data,
            commitment,
            signature,
            signing_key,
            _marker: PhantomData,
        }
    }

    /// Is the signature of this envelope valid?
    pub fn is_valid(&self, membership: &StaticCommittee) -> bool {
        membership.committee().contains(&self.signing_key)
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

impl<D: Committable> Envelope<D, Validated> {
    /// Create a (validated) envelope by signing data with a private key.
    pub fn signed(d: D, private_key: &PrivateKey, public_key: PublicKey) -> Self {
        let c = d.commit();
        let s = PublicKey::sign(private_key, c.as_ref()).expect("BLS signing never fails");
        Self::new(d, s, public_key)
    }

    /// A validated envelope can be cast to envelopes of other types.
    ///
    /// E.g. Validated -> Unchecked
    pub fn cast<S>(self) -> Envelope<D, S> {
        Envelope {
            data: self.data,
            commitment: self.commitment,
            signature: self.signature,
            signing_key: self.signing_key,
            _marker: PhantomData,
        }
    }
}
