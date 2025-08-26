use committable::{Commitment, Committable, RawCommitmentBuilder};
use constant_time_eq::constant_time_eq;
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{Committee, Keypair, PublicKey, Signature};

#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Encode, Decode,
)]
#[cbor(map)]
pub struct Signed<D: Committable> {
    #[cbor(n(0))]
    data: D,

    #[cbor(n(1), with = "adapters::commitment")]
    commitment: Commitment<D>,

    #[cbor(n(2))]
    signature: Signature,

    #[cbor(n(3))]
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
            signing_key: keypair.public_key(),
        }
    }

    pub fn is_valid(&self, membership: &Committee) -> bool {
        membership.contains_key(&self.signing_key)
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
        let sig = bincode::serde::encode_to_vec(self.signature, bincode::config::standard())
            .expect("serializing signature never fails");
        RawCommitmentBuilder::new("Signed")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .var_size_field("signature", &sig)
            .var_size_field("signing_key", &self.signing_key.to_bytes())
            .finalize()
    }
}
