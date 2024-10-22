use crate::consensus::vote::SailfishVote;

use super::certificate::{NoVoteData, TimeoutData, VertexCertificateData};

pub type TimeoutVote = SailfishVote<TimeoutData>;
pub type NoVoteVote = SailfishVote<NoVoteData>;
pub type VertexVote = SailfishVote<VertexCertificateData>;
