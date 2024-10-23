use std::collections::{BTreeMap, HashSet};

use anyhow::Result;
use committee::StaticCommittee;
use dag::Dag;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use vote::VoteAccumulator;

use crate::types::{certificate::Certificate, envelope::Envelope, message::{Action, Message, NoVote, Timeout}, vertex::Vertex, PublicKey, SecretKey};

mod dag;
mod vote;

pub mod committee;

pub struct Consensus {
    /// The public key of the node running this task.
    pub pkey: PublicKey,

    /// The private key of the node running this task.
    pub skey: SecretKey,

    /// The DAG of vertices
    pub dag: Dag,

    /// The quorum membership.
    pub committee: StaticCommittee,

    /// The current round number.
    pub round: ViewNumber,

    /// The set of vertices that we've received so far per round.
    pub vertices: BTreeMap<ViewNumber, HashSet<Vertex>>,

    /// The set of timeouts that we've received so far per round.
    pub timeouts: BTreeMap<ViewNumber, VoteAccumulator<Timeout>>,

    /// The set of no votes that we've received so far.
    pub no_votes: VoteAccumulator<NoVote>,
}

impl Consensus {
    pub fn new(pk: PublicKey, sk: SecretKey, committee: StaticCommittee) -> Self {
        Self {
            pkey: pk,
            skey: sk,
            dag: Dag::new(),
            round: ViewNumber::genesis(),
            vertices: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            no_votes: VoteAccumulator::new(committee.clone()),
            committee
        }
    }

    pub async fn timeout(&mut self, r: ViewNumber) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_message(&mut self, m: Message) -> Result<Vec<Action>> {
        match m {
            Message::Vertex(e) => self.handle_vertex(e).await,
            Message::Timeout(e) => self.handle_timeout(e).await,
            Message::TimeoutCert(c) => self.handle_timeout_cert(c).await,
            Message::NoVote(e) => self.handle_no_vote(e).await
        }
    }

    pub async fn handle_vertex(&mut self, x: Envelope<Vertex>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_no_vote(&mut self, x: Envelope<NoVote>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_timeout(&mut self, x: Envelope<Timeout>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }

    pub async fn handle_timeout_cert(&mut self, x: Certificate<Timeout>) -> Result<Vec<Action>> {
        Ok(Vec::new())
    }
}
