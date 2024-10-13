use std::fmt::Display;

use crate::types::timeout::{NoVoteData, TimeoutData};
use bincode::Options;
use committable::{Commitment, Committable};
use hotshot::types::{BLSPubKey, SignatureKey};
use hotshot_types::{data::ViewNumber, utils::bincode_opts};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SailfishCertificate<DATA: Committable> {
    /// The data this certificate is for.  I.e the thing that was voted on to create this Certificate
    data: DATA,

    /// The commitment of all the votes this cert should be signed over.
    vote_commitment: Commitment<DATA>,

    /// The round number this certificate is for.
    round: ViewNumber,

    /// The assembled signature for this certificate.
    signatures: Option<<BLSPubKey as SignatureKey>::QcType>,
}

impl<DATA: Committable> Display for SailfishCertificate<DATA> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SailfishCertificate(round: {})", self.round)
    }
}

impl<DATA: Committable> SailfishCertificate<DATA> {
    /// Returns the round number this certificate is for.
    pub fn round_number(&self) -> ViewNumber {
        self.round
    }
}

impl<DATA: Committable> SailfishCertificate<DATA> {
    /// Creates a new instance of `Certificate`.
    pub fn new(
        data: DATA,
        vote_commitment: Commitment<DATA>,
        round: ViewNumber,
        signatures: Option<<BLSPubKey as SignatureKey>::QcType>,
    ) -> Self {
        Self {
            data,
            vote_commitment,
            round,
            signatures,
        }
    }
}

pub fn serialize_signature<KEY: SignatureKey>(
    signatures: &<KEY as SignatureKey>::QcType,
) -> Vec<u8> {
    let mut signatures_bytes = vec![];
    signatures_bytes.extend("Yes".as_bytes());

    let (sig, proof) = KEY::sig_proof(signatures);
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

impl<DATA: Committable> Committable for SailfishCertificate<DATA> {
    fn commit(&self) -> Commitment<Self> {
        let signature_bytes = match self.signatures.as_ref() {
            Some(sigs) => serialize_signature::<BLSPubKey>(sigs),
            None => vec![],
        };

        committable::RawCommitmentBuilder::new("Certificate")
            .field("data", self.data.commit())
            .field("vote_commitment", self.vote_commitment)
            .field("round", self.round.commit())
            .var_size_field("signatures", &signature_bytes)
            .finalize()
    }
}

pub type TimeoutCertificate = SailfishCertificate<TimeoutData>;
pub type NoVoteCertificate = SailfishCertificate<NoVoteData>;
