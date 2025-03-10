use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{Committee, Keypair, PublicKey, Signature};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signed<D: Committable> {
    data: D,
    commitment: Commitment<D>,
    signature: Signature,
    signing_key: PublicKey,
}

impl<D: Committable> Signed<D> {
    pub fn new(d: D, keypair: &Keypair, deterministic: bool) -> Self {
        let c = d.commit();
        let s = keypair.sign(c.as_ref(), deterministic);
        Self {
            data: d,
            commitment: c,
            signature: s,
            signing_key: keypair.public_key(),
        }
    }

    pub fn is_valid(&self, membership: &Committee) -> bool {
        membership.contains_key(&self.signing_key)
            && self.data.commit() == self.commitment
            && self
                .signing_key
                .is_valid(self.commitment.as_ref(), &self.signature)
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
        let sig = bincode::serde::encode_to_vec(self.signature, bincode::config::legacy())
            .expect("serializing signature never fails");
        RawCommitmentBuilder::new("Signed")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .var_size_field("signature", &sig)
            .var_size_field("signing_key", &self.signing_key.as_bytes())
            .finalize()
    }
}
