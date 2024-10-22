use crate::consensus::{
    committee::StaticCommittee,
    vote::{HasRoundNumber, Voteable},
};
use bincode::Options;
use committable::{Commitment, Committable};
use ethereum_types::U256;
use hotshot::types::{BLSPubKey, SignatureKey};
use hotshot_types::{
    data::ViewNumber, traits::node_implementation::ConsensusTime, utils::bincode_opts,
};
use serde::{Deserialize, Serialize};

pub trait Certificate<VoteData: Voteable> {
    fn create_signed_certificate(
        vote_commitment: Commitment<VoteData>,
        data: VoteData,
        sig: <BLSPubKey as SignatureKey>::QcType,
        view: ViewNumber,
    ) -> Self;

    fn is_valid_cert(&self, membership: &StaticCommittee) -> bool;

    fn threshold(membership: &StaticCommittee) -> u64;

    fn data(&self) -> &VoteData;

    fn data_commitment(&self) -> Commitment<VoteData>;
}

/// A certificate which can be created by aggregating many simple votes on the commitment.
#[derive(Serialize, Deserialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct SailfishCertificate<VoteData: Voteable> {
    /// The data this certificate is for.  I.e the thing that was voted on to create this Certificate
    pub data: VoteData,

    /// commitment of all the votes this cert should be signed over
    pub vote_commitment: Commitment<VoteData>,

    /// Which round this QC relates to
    pub round_number: ViewNumber,

    /// assembled signature for certificate aggregation
    pub signatures: Option<<BLSPubKey as SignatureKey>::QcType>,
}

impl<VoteData: Voteable> SailfishCertificate<VoteData> {
    pub fn new(
        data: VoteData,
        vote_commitment: Commitment<VoteData>,
        round_number: ViewNumber,
        signatures: Option<<BLSPubKey as SignatureKey>::QcType>,
    ) -> Self {
        Self {
            data,
            vote_commitment,
            round_number,
            signatures,
        }
    }

    pub fn round_number(&self) -> ViewNumber {
        self.round_number
    }
}

impl<VoteData: Voteable> Certificate<VoteData> for SailfishCertificate<VoteData> {
    fn create_signed_certificate(
        vote_commitment: Commitment<VoteData>,
        data: VoteData,
        sig: <BLSPubKey as SignatureKey>::QcType,
        view: ViewNumber,
    ) -> Self {
        let vote_commitment_bytes: [u8; 32] = vote_commitment.into();

        SailfishCertificate {
            data,
            vote_commitment: Commitment::from_raw(vote_commitment_bytes),
            round_number: view,
            signatures: Some(sig),
        }
    }

    fn is_valid_cert(&self, membership: &StaticCommittee) -> bool {
        if self.round_number == ViewNumber::genesis() {
            return true;
        }

        let real_qc_pp = BLSPubKey::public_parameter(
            membership.stake_table(),
            U256::from(membership.success_threshold().get()),
        );
        let commit = self.data_commitment();
        BLSPubKey::check(
            &real_qc_pp,
            commit.as_ref(),
            self.signatures.as_ref().unwrap(),
        )
    }

    fn threshold(membership: &StaticCommittee) -> u64 {
        membership.success_threshold().get()
    }

    fn data(&self) -> &VoteData {
        &self.data
    }

    fn data_commitment(&self) -> Commitment<VoteData> {
        self.data.commit()
    }
}

pub fn serialize_signature(signatures: &<BLSPubKey as SignatureKey>::QcType) -> Vec<u8> {
    let mut signatures_bytes = vec![];
    signatures_bytes.extend("Yes".as_bytes());

    let (sig, proof) = BLSPubKey::sig_proof(signatures);
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

impl<VoteData: Voteable> Committable for SailfishCertificate<VoteData> {
    fn commit(&self) -> Commitment<Self> {
        let signature_bytes = match self.signatures.as_ref() {
            Some(sigs) => serialize_signature(sigs),
            None => vec![],
        };
        committable::RawCommitmentBuilder::new("Certificate")
            .field("data", self.data.commit())
            .field("vote_commitment", self.vote_commitment)
            .field("view number", self.round_number.commit())
            .var_size_field("signatures", &signature_bytes)
            .finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct TimeoutData {
    pub round: ViewNumber,
}

impl HasRoundNumber for TimeoutData {
    fn round_number(&self) -> ViewNumber {
        self.round
    }
}

impl Committable for TimeoutData {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("TimeoutData")
            .field("round", self.round.commit())
            .finalize()
    }
}

impl Voteable for TimeoutData {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NoVoteData {
    pub round: ViewNumber,
}

impl HasRoundNumber for NoVoteData {
    fn round_number(&self) -> ViewNumber {
        self.round
    }
}

impl Committable for NoVoteData {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("NoVoteData")
            .field("round", self.round.commit())
            .finalize()
    }
}

impl Voteable for NoVoteData {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct VertexCertificateData {
    pub round: ViewNumber,
    pub source: BLSPubKey,
}

impl HasRoundNumber for VertexCertificateData {
    fn round_number(&self) -> ViewNumber {
        self.round
    }
}

impl Committable for VertexCertificateData {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("VertexCertificateData")
            .field("round", self.round.commit())
            .constant_str("source")
            .var_size_bytes(&self.source.to_bytes())
            .finalize()
    }
}

impl Voteable for VertexCertificateData {}

pub type TimeoutCertificate = SailfishCertificate<TimeoutData>;
pub type NoVoteCertificate = SailfishCertificate<NoVoteData>;
pub type VertexCertificate = SailfishCertificate<VertexCertificateData>;

impl VertexCertificate {
    pub fn genesis(public_key: BLSPubKey) -> Self {
        let data = VertexCertificateData {
            round: ViewNumber::genesis(),
            source: public_key,
        };

        let vote_commitment = data.commit();

        Self {
            data,
            vote_commitment,
            round_number: ViewNumber::genesis(),
            signatures: None,
        }
    }
}
