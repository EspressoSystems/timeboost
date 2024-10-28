use std::collections::{BTreeMap, HashSet, VecDeque};
use std::mem;

use committee::StaticCommittee;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use tracing::{debug, instrument, trace, warn};
use vote::VoteAccumulator;

use crate::types::{
    block::Block,
    certificate::Certificate,
    envelope::{Envelope, Validated},
    message::{Action, Message, NoVote, Timeout},
    vertex::Vertex,
    NodeId, PrivateKey, PublicKey,
};

mod dag;
mod vote;

pub mod committee;

pub use dag::Dag;

/// A `NewVertex` may need to have a timeout or no-vote certificate set.
struct NewVertex(Vertex);

pub struct Consensus {
    /// The ID of the node running this consensus instance.
    id: NodeId,

    /// The public key of the node running this task.
    public_key: PublicKey,

    /// The private key of the node running this task.
    private_key: PrivateKey,

    /// The DAG of vertices
    dag: Dag,

    /// The quorum membership.
    committee: StaticCommittee,

    /// The current round number.
    round: ViewNumber,

    /// The last committed round number.
    committed_round: ViewNumber,

    /// The set of vertices that we've received so far.
    buffer: HashSet<Vertex>,

    /// The set of vertices that we've delivered so far.
    delivered: HashSet<Vertex>,

    /// The set of timeouts that we've received so far per round.
    timeouts: BTreeMap<ViewNumber, VoteAccumulator<Timeout>>,

    /// The set of no votes that we've received so far.
    no_votes: VoteAccumulator<NoVote>,

    /// Stack of leader vertices.
    leader_stack: Vec<Vertex>,

    /// Blocks of transtactions to include in vertex proposals.
    blocks: VecDeque<Block>,
}

impl Consensus {
    pub fn new(
        id: NodeId,
        public_key: PublicKey,
        private_key: PrivateKey,
        committee: StaticCommittee,
    ) -> Self {
        Self {
            id,
            public_key,
            private_key,
            dag: Dag::new(),
            round: ViewNumber::genesis(),
            committed_round: ViewNumber::genesis(),
            buffer: HashSet::new(),
            delivered: HashSet::new(),
            timeouts: BTreeMap::new(),
            no_votes: VoteAccumulator::new(committee.clone()),
            committee,
            leader_stack: Vec::new(),
            blocks: VecDeque::new(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn round(&self) -> ViewNumber {
        self.round
    }

    pub fn add_block(&mut self, b: Block) {
        self.blocks.push_back(b);
    }

    /// (Re-)start consensus.
    ///
    /// This continues with the highest round number found in the DAG (or else
    /// starts from the genesis round).
    pub fn go(&mut self, d: Dag) -> Vec<Action> {
        let r = d.max_round().unwrap_or(ViewNumber::genesis());

        self.dag = d;
        self.round = r;
        // TODO: Save and restore other states (committed_round, buffer, etc.)

        if r == ViewNumber::genesis() {
            let gen = Vertex::new(r, self.public_key);
            let env = Envelope::signed(gen, &self.private_key, self.public_key);
            return vec![Action::SendProposal(env)];
        }

        self.advance_from_round(r)
    }

    #[instrument(level = "trace", skip_all, fields(
        node      = %self.id,
        round     = %self.round,
        committed = %self.committed_round,
        buffered  = %self.buffer.len(),
        delivered = %self.delivered.len(),
        leaders   = %self.leader_stack.len(),
        timeouts  = %self.timeouts.len())
    )]
    pub fn handle_message(&mut self, m: Message) -> Vec<Action> {
        match m {
            Message::Vertex(e) => {
                let Some(e) = e.validated(&self.committee) else {
                    return Vec::new();
                };
                self.handle_vertex(e)
            }
            Message::NoVote(e) => {
                let Some(e) = e.validated(&self.committee) else {
                    return Vec::new();
                };
                self.handle_no_vote(e)
            }
            Message::Timeout(e) => {
                let Some(e) = e.validated(&self.committee) else {
                    return Vec::new();
                };
                self.handle_timeout(e)
            }
            Message::TimeoutCert(c) => self.handle_timeout_cert(c),
        }
    }

    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    pub fn timeout(&mut self, r: ViewNumber) -> Vec<Action> {
        debug_assert_eq!(r, self.round);
        let e = Envelope::signed(Timeout::new(r), &self.private_key, self.public_key);
        vec![Action::SendTimeout(e)]
    }

    #[instrument(level = "trace", skip_all, fields(
        node   = %self.id,
        round  = %self.round,
        vround = %e.data().round())
    )]
    pub fn handle_vertex(&mut self, e: Envelope<Vertex, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        if e.data().source() != e.signing_key() {
            warn!(src = %e.data().source(), sig = %e.signing_key(), "vertex sender != signer");
            return actions;
        }

        let vertex = e.into_data();

        if !(self.is_valid(&vertex) || vertex.is_genesis()) {
            return actions;
        }

        match self.try_to_add_to_dag(&vertex) {
            Err(()) => {
                self.buffer.insert(vertex);
            }
            Ok(a) => {
                actions.extend(a);

                // Since we managed to add another vertex, try to add all buffered vertices to the DAG too:
                let buffer = mem::take(&mut self.buffer);
                let mut retained = HashSet::new();
                for w in buffer.into_iter().filter(|w| w.round() <= vertex.round()) {
                    if let Ok(b) = self.try_to_add_to_dag(&w) {
                        actions.extend(b)
                    } else {
                        retained.insert(w);
                    }
                }
                debug_assert!(self.buffer.is_empty());
                self.buffer = retained;

                // Check if we can advance to the next round.

                if vertex.round() < self.round {
                    return actions;
                }

                if (self.dag.vertex_count(vertex.round()) as u64)
                    < self.committee.success_threshold().get()
                {
                    return actions;
                }

                actions.extend(self.advance_from_round(vertex.round()));
            }
        }

        actions
    }

    pub fn handle_no_vote(&mut self, _x: Envelope<NoVote, Validated>) -> Vec<Action> {
        Vec::new()
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    pub fn handle_timeout(&mut self, e: Envelope<Timeout, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        let round = e.data().round();

        if round < self.round {
            debug! {
                node  = %self.id,
                round = %self.round,
                r     = %round,
                "ignoring old timeout"
            }
            return actions;
        }

        let accum = self
            .timeouts
            .entry(e.data().round())
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        if !accum.add(e) {
            warn! {
                node  = %self.id,
                round = %self.round,
                r     = %round,
                "could not add timeout to vote accumulator"
            }
            return actions;
        }

        // Have we received more than f timeouts?
        if accum.votes() as u64 == self.committee.failure_threshold().get() {
            let e = Envelope::signed(Timeout::new(round), &self.private_key, self.public_key);
            actions.push(Action::SendTimeout(e))
        }

        // Have we received more than 2f timeouts?
        if accum.votes() as u64 == self.committee.success_threshold().get() {
            let cert = accum
                .certificate()
                .expect("> 2f votes => certificate is available");
            actions.push(Action::SendTimeoutCert(cert.clone()))
        }

        actions
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    pub fn handle_timeout_cert(&mut self, _x: Certificate<Timeout>) -> Vec<Action> {
        Vec::new()
    }

    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn advance_from_round(&mut self, round: ViewNumber) -> Vec<Action> {
        let mut actions = Vec::new();

        // With a leader vertex we can move on to the next round immediately.
        if self.leader_vertex(round).is_some() {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let v = self.create_new_vertex(self.round);
            actions.extend(self.add_and_broadcast_vertex(v.0));
            return actions;
        }

        // Otherwise we need a timeout certificate.
        let Some(tc) = self
            .timeouts
            .get_mut(&round)
            .and_then(|t| t.certificate())
            .cloned()
        else {
            return actions;
        };

        // We inform the leader of the next round that we did not note in the previous round.
        let e = Envelope::signed(NoVote::new(round), &self.private_key, self.public_key);
        let leader = self.committee.leader(round + 1);
        actions.push(Action::SendNoVote(leader, e));

        // If we are not ourselves leader of the next round we can move to it directly.
        if self.public_key != leader {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let NewVertex(mut v) = self.create_new_vertex(self.round);
            v.set_timeout(tc);
            actions.extend(self.add_and_broadcast_vertex(v));
            return actions;
        }

        // As leader of the next round we need to wait for > 2f no-votes of the current round
        // since we have no leader vertex.
        let Some(nc) = self.no_votes.certificate().cloned() else {
            return actions;
        };

        self.round = round + 1;
        actions.push(Action::ResetTimer(self.round));
        let NewVertex(mut v) = self.create_new_vertex(self.round);
        v.set_no_vote(nc);
        v.set_timeout(tc);
        actions.extend(self.add_and_broadcast_vertex(v));
        actions
    }

    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn add_and_broadcast_vertex(&mut self, v: Vertex) -> Vec<Action> {
        self.dag.add(v.clone());
        let mut actions = Vec::new();
        let e = Envelope::signed(v, &self.private_key, self.public_key);
        actions.push(Action::SendProposal(e));
        actions
    }

    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn create_new_vertex(&mut self, r: ViewNumber) -> NewVertex {
        let prev = self.dag.vertices(r - 1);

        let mut new = Vertex::new(r, self.public_key);
        new.set_block(self.blocks.pop_front().unwrap_or_default());
        new.add_strong_edges(prev.map(Vertex::id).cloned());

        // Every vertex in our DAG has > 2f edges to the previous round:
        debug_assert!(new.strong_edge_count() as u64 >= self.committee.success_threshold().get());

        // Set weak edges:
        for r in (1..r.u64() - 1).rev() {
            for v in self.dag.vertices(ViewNumber::new(r)) {
                if !self.dag.is_connected(&new, v, false) {
                    new.add_weak_edge(v.id().clone());
                }
            }
        }

        NewVertex(new)
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round, vround = %v.round()))]
    fn try_to_add_to_dag(&mut self, v: &Vertex) -> Result<Vec<Action>, ()> {
        if !v
            .edges()
            .all(|id| self.dag.vertex(id.round(), id.source()).is_some())
        {
            debug! {
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                "not all vertices are present in dag"
            }
            return Err(());
        }

        self.dag.add(v.clone());

        if v.is_genesis() {
            // A genesis vertex has no edges to prior rounds.
            return Ok(Vec::new());
        }

        if self.dag.vertices(v.round()).count() as u64 >= self.committee.success_threshold().get() {
            // We have enough edges => try to commit the leader vertex:
            let Some(l) = self.leader_vertex(v.round() - 1).cloned() else {
                warn! {
                    node   = %self.id,
                    round  = %self.round,
                    vround = %v.round(),
                    "no leader vertex in vround - 1 => can not commit"
                }
                return Ok(Vec::new());
            };
            // If enough edges to the leader of the previous round exist we can commit the leader.
            if self
                .dag
                .vertices(v.round())
                .filter(|v| self.dag.is_connected(v, &l, true))
                .count() as u64
                >= self.committee.success_threshold().get()
            {
                return Ok(self.commit_leader(l));
            }
        }

        Ok(Vec::new())
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round, vround = %v.round()))]
    fn commit_leader(&mut self, mut v: Vertex) -> Vec<Action> {
        self.leader_stack.push(v.clone());
        for r in ((self.committed_round + 1).u64()..v.round().u64()).rev() {
            let Some(l) = self.leader_vertex(ViewNumber::new(r)).cloned() else {
                continue; // TODO: This should not happen
            };
            if self.dag.is_connected(&v, &l, true) {
                self.leader_stack.push(l.clone());
                v = l
            }
        }
        self.committed_round = v.round();
        trace!(commit = %self.committed_round, "committed round");
        self.order_vertices()
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    fn order_vertices(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut delivered = mem::take(&mut self.delivered);
        while let Some(v) = self.leader_stack.pop() {
            for to_deliver in self
                .dag
                .vertices_from(ViewNumber::genesis() + 1)
                .filter(|w| self.dag.is_connected(&v, w, false))
            {
                if delivered.contains(to_deliver) {
                    continue;
                }
                let b = to_deliver.block().clone();
                let r = to_deliver.round();
                let s = *to_deliver.source();
                actions.push(Action::Deliver(b, r, s));
                delivered.insert(to_deliver.clone());
            }
        }
        self.delivered = delivered;
        actions
    }

    /// Validate an incoming vertex.
    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round, vround = %v.round()))]
    fn is_valid(&self, v: &Vertex) -> bool {
        if (v.strong_edge_count() as u64) < self.committee.success_threshold().get() {
            warn! {
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex has not enough strong edges"
            }
            return false;
        }

        let Some(l) = self.leader_vertex(v.round() - 1) else {
            warn! {
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "no leader vertex for vround - 1 found"
            }
            return false;
        };

        if v.has_strong_edge(l.id()) {
            return true;
        }

        if let Some(cert) = v.timeout_cert() {
            if cert.data().round() != v.round() - 1 {
                warn! {
                    node   = %self.id,
                    round  = %self.round,
                    vround = %v.round(),
                    vsrc   = %v.source(),
                    "vertex has timeout certificate from invalid round"
                }
                return false;
            }
            if !cert.is_valid_quorum(&self.committee) {
                warn! {
                    node   = %self.id,
                    round  = %self.round,
                    vround = %v.round(),
                    vsrc   = %v.source(),
                    "vertex has timeout certificate with invalid quorum"
                }
                return false;
            }
        }

        if v.source() != &self.committee.leader(v.round()) {
            return true;
        }

        if let Some(cert) = v.no_vote_cert() {
            if cert.data().round() != v.round() - 1 {
                warn! {
                    node   = %self.id,
                    round  = %self.round,
                    vround = %v.round(),
                    vsrc   = %v.source(),
                    "vertex has no-vote certificate from invalid round"
                }
                return false;
            }
            if !cert.is_valid_quorum(&self.committee) {
                warn! {
                    node   = %self.id,
                    round  = %self.round,
                    vround = %v.round(),
                    vsrc   = %v.source(),
                    "vertex has no-vote certificate with invalid quorum"
                }
                return false;
            }
        }

        true
    }

    fn leader_vertex(&self, r: ViewNumber) -> Option<&Vertex> {
        self.dag.vertex(r, &self.committee.leader(r))
    }
}
