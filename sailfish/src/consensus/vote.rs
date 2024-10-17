use hotshot::traits::election::static_committee::StaticCommittee;
use hotshot_types::{
    message::UpgradeLock,
    traits::node_implementation::Versions,
    vote::{Certificate, Vote, VoteAccumulator},
};
use std::{collections::HashMap, marker::PhantomData};

use crate::impls::sailfish_types::SailfishTypes;

pub async fn create_vote_accumulator<
    VertexVote: Vote<SailfishTypes>,
    VertexCertificate: Certificate<SailfishTypes, Voteable = VertexVote::Commitment>,
    V: Versions,
>(
    vote: &VertexVote,
    quorum_membership: &StaticCommittee<SailfishTypes>,
) -> VoteAccumulator<SailfishTypes, VertexVote, VertexCertificate, V> {
    let mut accumulator = VoteAccumulator {
        vote_outcomes: HashMap::new(),
        signers: HashMap::new(),
        // We don't care about this in Sailfish.
        upgrade_lock: UpgradeLock::new(),
        phantom: PhantomData,
    };

    accumulator.accumulate(vote, quorum_membership).await;

    accumulator
}
