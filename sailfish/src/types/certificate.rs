use crate::{
    impls::sailfish_types::SailfishTypes,
    types::timeout::{NoVoteData, TimeoutData},
};
use committable::{Commitment, Committable};
use hotshot::types::BLSPubKey;
use hotshot_types::{
    data::ViewNumber,
    simple_certificate::{OneHonestThreshold, SimpleCertificate, SuccessThreshold},
    traits::node_implementation::ConsensusTime,
};
use serde::{Deserialize, Serialize};

use super::vertex::Vertex;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct VertexCertificateData {
    commitment: Commitment<Vertex>,
    round: ViewNumber,
}

impl Committable for VertexCertificateData {
    fn commit(&self) -> Commitment<Self> {
        committable::RawCommitmentBuilder::new("VertexCertificateData")
            .var_size_bytes(self.commitment.as_ref())
            .field("view_number", self.round.commit())
            .finalize()
    }
}

impl VertexCertificateData {
    pub fn new(commitment: Commitment<Vertex>, round: ViewNumber) -> Self {
        VertexCertificateData { commitment, round }
    }

    pub fn genesis(public_key: BLSPubKey) -> Self {
        let vertex = Vertex::genesis(public_key);
        VertexCertificateData {
            commitment: vertex.commit(),
            round: ViewNumber::genesis(),
        }
    }
}

pub type VertexCertificate =
    SimpleCertificate<SailfishTypes, VertexCertificateData, SuccessThreshold>;
pub type TimeoutCertificate = SimpleCertificate<SailfishTypes, TimeoutData, OneHonestThreshold>;
pub type NoVoteCertificate = SimpleCertificate<SailfishTypes, NoVoteData, OneHonestThreshold>;

pub fn make_genesis_vertex_certificate(public_key: BLSPubKey) -> VertexCertificate {
    let data = VertexCertificateData::genesis(public_key);
    let commitment = data.commit();
    VertexCertificate::new(
        data,
        commitment,
        ViewNumber::genesis(),
        None,
        std::marker::PhantomData,
    )
}
