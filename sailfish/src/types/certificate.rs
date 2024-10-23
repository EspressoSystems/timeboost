use crate::consensus::committee::StaticCommittee;
use bincode::Options;
use bitvec::vec::BitVec;
use committable::{Commitment, Committable};
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use hotshot_types::utils::bincode_opts;
use serde::{Deserialize, Serialize};

use super::{vertex::Vertex, PrivateKey, PublicKey, QuorumSignature};

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
            U256::from(membership.success_threshold().get()),
        );

        let commit = self.commitment();
        PublicKey::check(&real_qc_pp, commit.as_ref(), &self.quorum)
    }
}

impl Certificate<Vertex> {
    pub fn genesis(private_key: &PrivateKey, public_key: PublicKey) -> Self {
        let d = Vertex::genesis(public_key);
        let c = d.commit();
        let s = PublicKey::sign(private_key, c.as_ref()).expect("Signing never fails");
        Self {
            data: d,
            commitment: c,
            // Fake the quorum signature. Validation will fail.
            // It is up to the caller to handle the genesis case.
            quorum: (s, BitVec::new()),
        }
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
    let proof_bytes = bincode_opts()
        .serialize(&proof.as_bitslice())
        .expect("This serialization shouldn't be able to fail");
    signatures_bytes.extend("bitvec proof".as_bytes());
    signatures_bytes.extend(proof_bytes.as_slice());
    let sig_bytes = bincode_opts()
        .serialize(&sig)
        .expect("This serialization shouldn't be able to fail");
    signatures_bytes.extend("aggregated signature".as_bytes());
    signatures_bytes.extend(sig_bytes.as_slice());
    signatures_bytes
}
