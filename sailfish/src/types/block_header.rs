use crate::types::certificate::{NoVoteCertificate, TimeoutCertificate};
use hotshot::types::{BLSPubKey, SignatureKey};
use hotshot_types::data::ViewNumber;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub author: BLSPubKey,

    /// The round number of the block.
    pub round: ViewNumber,

    /// The signature of the block.
    pub signature: <BLSPubKey as SignatureKey>::QcType,

    /// The no-vote certificate for `v.round - 1`.
    pub no_vote_certificate: Option<NoVoteCertificate>,

    /// The timeout certificate for `v.round - 1`.
    pub timeout_certificate: Option<TimeoutCertificate>,
}
