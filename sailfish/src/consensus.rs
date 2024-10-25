use std::collections::{BTreeMap, HashSet, VecDeque};
use std::mem;

use committee::StaticCommittee;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use tracing::{debug, trace, warn};
use vote::VoteAccumulator;

use crate::types::{
    block::Block,
    certificate::Certificate,
    envelope::{Envelope, Unchecked},
    message::{Action, Message, NoVote, Timeout},
    vertex::Vertex,
    NodeId, PrivateKey, PublicKey,
};

mod dag;
mod vote;

pub mod committee;

pub use dag::Dag;

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

        self.advance_round(r + 1)
    }

    pub fn handle_message(&mut self, m: Message) -> Vec<Action> {
        match m {
            Message::Vertex(e) => self.handle_vertex(e),
            Message::Timeout(e) => self.handle_timeout(e),
            Message::TimeoutCert(c) => self.handle_timeout_cert(c),
            Message::NoVote(e) => self.handle_no_vote(e),
        }
    }

    pub fn timeout(&mut self, r: ViewNumber) -> Vec<Action> {
        trace!(node = %self.id, round = %self.round, %r, "timeout");
        debug_assert_eq!(r, self.round);
        let e = Envelope::signed(Timeout::new(r), &self.private_key, self.public_key);
        vec![Action::SendTimeout(e)]
    }

    pub fn handle_vertex(&mut self, e: Envelope<Vertex, Unchecked>) -> Vec<Action> {
        trace!(node = %self.id, round = %self.round, vround = %e.data().round(), "handle_vertex");
        let mut actions = Vec::new();

        let Some(e) = e.validated(&self.committee) else {
            return actions;
        };

        if e.data().source() != e.signing_key() {
            trace! {
                node  = %self.id,
                round = %self.round,
                src   = %e.data().source(),
                sig   = %e.signing_key(),
                "vertex sender != signer"
            }
            return actions;
        }

        let vertex = e.into_data();

        if !vertex.is_genesis() {
            if (vertex.strong_edge_count() as u64) < self.committee.success_threshold().get() {
                debug! {
                    node   = %self.id,
                    round  = %self.round,
                    vround = %vertex.round(),
                    "rejecting vertex with not enough strong edges"
                }
                return actions;
            }

            if !self.is_valid(&vertex) {
                debug! {
                    node   = %self.id,
                    round  = %self.round,
                    vround = %vertex.round(),
                    "rejecting invalid vertex"
                }
                return actions;
            }
        }

        match self.try_to_add_to_dag(&vertex) {
            Err(()) => {
                self.buffer.insert(vertex);
            }
            Ok(a) => {
                actions.extend(a);
                // Try to add all buffered vertices to the DAG too:
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

                // Check if we can advance to vertex round + 1:

                if vertex.round() < self.round {
                    return actions;
                }

                if (self.dag.vertices(vertex.round()).count() as u64)
                    < self.committee.success_threshold().get()
                {
                    return actions;
                }

                if self.leader_vertex(vertex.round()).is_some()
                    || self
                        .timeouts
                        .get_mut(&vertex.round())
                        .and_then(|t| t.certificate())
                        .is_some()
                {
                    actions.extend(self.advance_round(vertex.round() + 1))
                }
            }
        }

        actions
    }

    pub fn handle_no_vote(&mut self, _x: Envelope<NoVote, Unchecked>) -> Vec<Action> {
        Vec::new()
    }

    pub fn handle_timeout(&mut self, e: Envelope<Timeout, Unchecked>) -> Vec<Action> {
        trace!(node = %self.id, round = %self.round, "handle_timeout");
        let mut actions = Vec::new();

        let Some(e) = e.validated(&self.committee) else {
            return actions;
        };

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

    pub fn handle_timeout_cert(&mut self, _x: Certificate<Timeout>) -> Vec<Action> {
        Vec::new()
    }

    fn advance_round(&mut self, r: ViewNumber) -> Vec<Action> {
        trace!(node = %self.id, round = %self.round, %r, "advance_round");
        debug_assert_ne!(r, ViewNumber::genesis());

        let mut actions = Vec::new();

        if self.leader_vertex(r - 1).is_some() {
            self.round = r;
            actions.push(Action::ResetTimer(r));
            actions.extend(self.broadcast_vertex(r));
            return actions;
        }

        let e = Envelope::signed(NoVote::new(r - 1), &self.private_key, self.public_key);
        let leader = self.committee.leader(r);
        actions.push(Action::SendNoVote(leader, e));

        // As leader of the current round we need to wait for > 2f no-votes
        // or a leader vertex, otherwise we can move on to the next round.
        if self.public_key != leader || self.no_votes.certificate().is_some() {
            self.round = r;
            actions.push(Action::ResetTimer(r));
            actions.extend(self.broadcast_vertex(r));
        }

        actions
    }

    fn broadcast_vertex(&mut self, r: ViewNumber) -> Vec<Action> {
        trace!(node = %self.id, round = %self.round, %r, "broadcast_vertex");
        let mut actions = Vec::new();
        let v = self.create_new_vertex(r);
        if let Ok(a) = self.try_to_add_to_dag(&v) {
            actions.extend(a)
        }
        let e = Envelope::signed(v, &self.private_key, self.public_key);
        actions.push(Action::SendProposal(e));
        actions
    }

    fn create_new_vertex(&mut self, r: ViewNumber) -> Vertex {
        trace!(node = %self.id, round = %self.round, %r, "create_new_vertex");

        let leader = self.committee.leader(r - 1);
        let prev = self.dag.vertices(r - 1);

        let mut new = Vertex::new(r, self.public_key);
        new.set_block(self.blocks.pop_front().unwrap_or_default());
        new.add_strong_edges(prev.map(Vertex::id).cloned());

        // Set weak edges:
        for r in (1..r.u64() - 1).rev() {
            for v in self.dag.vertices(ViewNumber::new(r)) {
                if !self.dag.is_connected(&new, v, false) {
                    new.add_weak_edge(v.id().clone());
                }
            }
        }

        // Set timeout and no-vote certificates:
        if self.leader_vertex(r - 1).is_none() {
            let t = self
                .timeouts
                .get_mut(&(r - 1))
                .expect("no leader vertex => timeout cert")
                .certificate()
                .expect("> 2f timeouts");
            new.set_timeout(t.clone());

            if self.public_key == leader {
                let n = self.no_votes.certificate().expect("> 2f no-votes");
                new.set_no_vote(n.clone());
            }
        }

        new
    }

    fn try_to_add_to_dag(&mut self, v: &Vertex) -> Result<Vec<Action>, ()> {
        trace!(node = %self.id, round = %self.round, vround = %v.round(), "try_to_add_to_dag");

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

    fn commit_leader(&mut self, mut v: Vertex) -> Vec<Action> {
        trace!(node = %self.id, round = %self.round, vround = %v.id(), "commit_leader");
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
        trace!(node = %self.id, round = %self.round, commit = %self.committed_round, "committed round");
        self.order_vertices()
    }

    fn order_vertices(&mut self) -> Vec<Action> {
        trace!(node = %self.id, round = %self.round, "order_vertices");
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

    fn is_valid(&self, v: &Vertex) -> bool {
        trace!(node = %self.id, round = %self.round, vround = %v.round(), "is_valid");

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
