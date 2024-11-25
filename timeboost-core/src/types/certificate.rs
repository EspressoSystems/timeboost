use crate::types::committee::StaticCommittee;
use committable::{Commitment, Committable};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use timeboost_crypto::traits::signature_key::SignatureKey;

use super::{PublicKey, QuorumSignature};

#[derive(Serialize, Deserialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct Certificate<D: Committable> {
    data: D,
    commitment: Commitment<D>,
    quorum: QuorumSignature,
}

impl<D: Committable> Certificate<D> {
    pub fn new(d: D, q: QuorumSignature) -> Self {
        let c = d.commit();
        Self {
            data: d,
            commitment: c,
            quorum: q,
        }
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn commitment(&self) -> Commitment<D> {
        self.commitment
    }

    pub fn is_valid_quorum(&self, membership: &StaticCommittee) -> bool {
        let real_qc_pp = PublicKey::public_parameter(
            membership.stake_table(),
            U256::from(membership.quorum_size().get()),
        );
        let commit = self.commitment();
        if self.data.commit() != commit {
            return false;
        }
        PublicKey::check(&real_qc_pp, commit.as_ref(), &self.quorum)
    }
}

impl<D: Committable> Committable for Certificate<D> {
    fn commit(&self) -> Commitment<Self> {
        let quorum_bytes = serialize_signature(&self.quorum);

        committable::RawCommitmentBuilder::new("Certificate")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .var_size_field("quorum", &quorum_bytes)
            .finalize()
    }
}

pub fn serialize_signature(signatures: &QuorumSignature) -> Vec<u8> {
    let mut signatures_bytes = vec![];
    signatures_bytes.extend("Yes".as_bytes());

    let (sig, proof) = PublicKey::sig_proof(signatures);
    let proof_bytes = bincode::serialize(&proof.as_bitslice())
        .expect("This serialization shouldn't be able to fail");
    signatures_bytes.extend("bitvec proof".as_bytes());
    signatures_bytes.extend(proof_bytes.as_slice());
    let sig_bytes = bincode::serialize(&sig).expect("This serialization shouldn't be able to fail");
    signatures_bytes.extend("aggregated signature".as_bytes());
    signatures_bytes.extend(sig_bytes.as_slice());
    signatures_bytes
}
