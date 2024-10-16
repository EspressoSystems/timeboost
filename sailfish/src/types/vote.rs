use hotshot_types::simple_vote::SimpleVote;

use crate::impls::sailfish_types::SailfishTypes;

use super::{
    timeout::{NoVoteData, TimeoutData},
    vertex::Vertex,
};

pub type VertexVote = SimpleVote<SailfishTypes, Vertex>;
pub type TimeoutVote = SimpleVote<SailfishTypes, TimeoutData>;
pub type NoVoteVote = SimpleVote<SailfishTypes, NoVoteData>;
