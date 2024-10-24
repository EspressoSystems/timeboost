use anyhow::Result;
use committable::{Commitment, Committable};
use hotshot::types::SignatureKey;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

use crate::{
    consensus::committee::StaticCommittee,
    types::{PrivateKey, PublicKey, Signature},
};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Envelope<D: Committable> {
    data: D,
    commitment: Commitment<D>,
    signature: Signature,
    signing_key: PublicKey,
}

impl<D: Committable> Envelope<D> {
    pub fn new(data: D, signature: Signature, signing_key: PublicKey) -> Self {
        let commitment = data.commit();
        Self {
            data,
            commitment,
            signature,
            signing_key,
        }
    }

    pub fn sign(d: D, private_key: &PrivateKey, public_key: PublicKey) -> Result<Self> {
        let c = d.commit();
        let s = PublicKey::sign(private_key, c.as_ref())?;
        Ok(Self::new(d, s, public_key))
    }

    pub fn is_valid(&self, membership: &StaticCommittee) -> bool {
        membership.committee().contains(&self.signing_key)
            && self
                .signing_key
                .validate(&self.signature, self.commitment.as_ref())
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn into_data(self) -> D {
        self.data
    }

    pub fn commitment(&self) -> Commitment<D> {
        self.commitment
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signing_key(&self) -> &PublicKey {
        &self.signing_key
    }
}
