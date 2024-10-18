use hotshot_types::simple_vote::SimpleVote;

use crate::impls::sailfish_types::SailfishTypes;

use super::{
    certificate::VertexCertificateData,
    timeout::{NoVoteData, TimeoutData},
};

pub type VertexVote = SimpleVote<SailfishTypes, VertexCertificateData>;
pub type TimeoutVote = SimpleVote<SailfishTypes, TimeoutData>;
pub type NoVoteVote = SimpleVote<SailfishTypes, NoVoteData>;
