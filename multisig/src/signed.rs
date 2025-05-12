use committable::{Commitment, Committable, RawCommitmentBuilder};
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};

use crate::{Committee, Keypair, PublicKey, Signature, Versioned};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signed<D: Committable> {
    data: Versioned<D>,
    commitment: Commitment<Versioned<D>>,
    signature: Signature,
    signing_key: PublicKey,
}

impl<D: Committable> Signed<D> {
    pub fn new(d: Versioned<D>, keypair: &Keypair, deterministic: bool) -> Self {
        let c = d.commit();
        let s = keypair.sign(c.as_ref(), deterministic);
        Self {
            data: d,
            commitment: c,
            signature: s,
            signing_key: keypair.public_key(),
        }
    }

    #[must_use]
    pub fn is_valid(&self, comm: &Committee) -> bool {
        comm.at(self.data.version())
            .map(|c| c.contains_key(&self.signing_key))
            .unwrap_or(false)
            && constant_time_eq(self.data.commit().as_ref(), self.commitment.as_ref())
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

    pub fn commitment(&self) -> &Commitment<Versioned<D>> {
        &self.commitment
    }

    pub fn data(&self) -> &Versioned<D> {
        &self.data
    }

    pub fn into_data(self) -> Versioned<D> {
        self.data
    }
}

impl<D: Committable> Committable for Signed<D> {
    fn commit(&self) -> Commitment<Self> {
        let sig = bincode::serde::encode_to_vec(self.signature, bincode::config::standard())
            .expect("serializing signature never fails");
        RawCommitmentBuilder::new("Signed")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .var_size_field("signature", &sig)
            .var_size_field("signing_key", &self.signing_key.as_bytes())
            .finalize()
    }
}
