use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use committee::StaticCommittee;
use dag::Dag;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use vote::VoteAccumulator;

use crate::types::{
    certificate::Certificate,
    envelope::Envelope,
    message::{Action, Message, NoVote, Timeout},
    vertex::Vertex,
    PrivateKey, PublicKey,
};

mod dag;
mod vote;

pub mod committee;

pub struct Consensus {
    /// The public key of the node running this task.
    public_key: PublicKey,

    /// The private key of the node running this task.
    #[allow(unused)]
    private_key: PrivateKey,

    /// The DAG of vertices
    #[allow(unused)]
    dag: Dag,

    /// The quorum membership.
    #[allow(unused)]
    committee: StaticCommittee,

    /// The current round number.
    round: ViewNumber,

    /// The set of vertices that we've received so far per round.
    #[allow(unused)]
    vertices: BTreeMap<ViewNumber, HashSet<Vertex>>,

    /// The set of timeouts that we've received so far per round.
    #[allow(unused)]
    timeouts: BTreeMap<ViewNumber, VoteAccumulator<Timeout>>,

    /// The set of no votes that we've received so far.
    #[allow(unused)]
    no_votes: VoteAccumulator<NoVote>,
}

impl Consensus {
    pub fn new(public_key: PublicKey, private_key: PrivateKey, committee: StaticCommittee) -> Self {
        Self {
            public_key,
            private_key,
            dag: Dag::new(),
            round: ViewNumber::genesis(),
            vertices: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            no_votes: VoteAccumulator::new(committee.clone()),
            committee,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn round(&self) -> ViewNumber {
        self.round
    }

    pub async fn timeout(&mut self, _r: ViewNumber) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_message(&mut self, m: Message) -> Result<Vec<Action>> {
        match m {
            Message::Vertex(e) => self.handle_vertex(e).await,
            Message::Timeout(e) => self.handle_timeout(e).await,
            Message::TimeoutCert(c) => self.handle_timeout_cert(c).await,
            Message::NoVote(e) => self.handle_no_vote(e).await,
        }
    }

    pub async fn handle_vertex(&mut self, _x: Envelope<Vertex>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_no_vote(&mut self, _x: Envelope<NoVote>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_timeout(&mut self, _x: Envelope<Timeout>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_timeout_cert(&mut self, _x: Certificate<Timeout>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }
}
