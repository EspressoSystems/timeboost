use committable::{Commitment, Committable, RawCommitmentBuilder};
use hotshot::types::SignatureKey;
use serde::{Deserialize, Serialize};

use crate::types::{committee::StaticCommittee, PublicKey, Signature};

use super::Keypair;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Signed<D: Committable> {
    data: D,
    commitment: Commitment<D>,
    signature: Signature,
    signing_key: PublicKey,
}

impl<D: Committable> Signed<D> {
    pub fn new(d: D, keypair: &Keypair) -> Self {
        let c = d.commit();
        let s = keypair.sign(c.as_ref());
        Self {
            data: d,
            commitment: c,
            signature: s,
            signing_key: *keypair.public_key(),
        }
    }

    pub fn is_valid(&self, membership: &StaticCommittee) -> bool {
        membership.committee().contains(&self.signing_key)
            && self.data.commit() == self.commitment
            && self
                .signing_key
                .validate(&self.signature, self.commitment.as_ref())
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

impl<D: Committable> Committable for Signed<D> {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Signed")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .var_size_field("signature", &bincode::serialize(&self.signature).unwrap()) // TODO
            .var_size_field("signing_key", &self.signing_key.to_bytes())
            .finalize()
    }
}
