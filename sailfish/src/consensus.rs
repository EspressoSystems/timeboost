use std::collections::{BTreeMap, HashSet, VecDeque};

use committee::StaticCommittee;
use dag::Dag;
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use tracing::{trace, warn};
use vote::VoteAccumulator;

use crate::types::{
    block::Block, certificate::Certificate, envelope::{Envelope, Unchecked}, message::{Action, Message, NoVote, Timeout}, vertex::Vertex, PrivateKey, PublicKey
};

mod dag;
mod vote;

pub mod committee;

pub struct Consensus {
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
    blocks: VecDeque<Block>
}

impl Consensus {
    pub fn new(public_key: PublicKey, private_key: PrivateKey, committee: StaticCommittee) -> Self {
        Self {
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
            blocks: VecDeque::new()
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
    pub fn go(&mut self, mut d: Dag) -> Vec<Action> {
        let r = d.max_round().unwrap_or(ViewNumber::genesis());

        if r == ViewNumber::genesis() {
            d.add(Vertex::new(r, self.public_key))
        }

        self.dag = d;
        self.round = r;
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
        trace!(id = %self.public_key, %r, "timeout");
        debug_assert_eq!(r, self.round);
        let e = Envelope::signed(Timeout::new(r), &self.private_key, self.public_key);
        vec![Action::SendTimeout(e)]
    }

    pub fn handle_vertex(&mut self, e: Envelope<Vertex, Unchecked>) -> Vec<Action> {
        trace!(id = %self.public_key, current = %self.round, "handle_vertex");
        let mut actions = Vec::new();
        let Some(e) = e.validated(&self.committee) else {
            return actions
        };
        let v = e.into_data();
        let r = v.id().round();
        // if v.strong_edge_count() as u64 > self.committee.success_threshold().get() && self.is_valid(&v) {
        //     match self.try_to_add_to_dag(v) {
        //         Err(()) => {
        //             self.buffer.insert(v);
        //         }
        //         Ok(mut actions) => {
        //             for w in self.buffer.iter().filter(|w| w.id().round() <= r) {
        //                 if let Ok(b) = self.try_to_add_to_dag(w.clone()) {
        //                     actions.extend(b)
        //                 }
        //             }
        //             let Some(e) = self.dag.vertex(r, v.id().source()) else {
        //                 return actions
        //             };
        //             // if r >= self.round && e.edge_count() as u64 > self.committee.success_threshold().get() && (self.leader_vertex(r).is_some()) || e.round.timeouts.len() > 2 * self.max_fail { // 36
        //             //     actions.extend(self.advance_round(r + 1));
        //             //     return actions
        //             // }
        //             return actions
        //         }
        //     }

        // }
        actions
    }

    pub fn handle_no_vote(&mut self, _x: Envelope<NoVote, Unchecked>) -> Vec<Action> {
        Vec::new()
    }

    pub fn handle_timeout(&mut self, e: Envelope<Timeout, Unchecked>) -> Vec<Action> {
        trace!(id = %self.public_key, current = %self.round, "handle_timeout");
        let mut actions = Vec::new();
        let Some(e) = e.validated(&self.committee) else {
            return actions
        };
        let round = e.data().round();
        let accum = self.timeouts
            .entry(e.data().round())
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        accum.add(e);
        if accum.votes() as u64 == self.committee.failure_threshold().get() {
            let e = Envelope::signed(Timeout::new(round), &self.private_key, self.public_key);
            actions.push(Action::SendTimeout(e))
        }
        if let Some(cert) = accum.certificate() {
            actions.push(Action::SendTimeoutCert(cert.clone()))
        }
        actions
    }

    pub fn handle_timeout_cert(&mut self, _x: Certificate<Timeout>) -> Vec<Action> {
        Vec::new()
    }

    fn advance_round(&mut self, r: ViewNumber) -> Vec<Action> {
        trace!(id = %self.public_key, current = %self.round, %r, "advance_round");
        debug_assert_ne!(r, ViewNumber::genesis());
        let mut actions = Vec::new();
        if self.leader_vertex(r - 1).is_none() {
            let e = Envelope::signed(NoVote::new(r - 1), &self.private_key, self.public_key);
            let leader = self.committee.leader(r);
            actions.push(Action::SendNoVote(leader, e));
            if self.public_key != leader {
                self.round = r;
                actions.push(Action::ResetTimer(r));
                actions.extend(self.broadcast_vertex(r))
            }
        } else {
            self.round = r;
            actions.push(Action::ResetTimer(r));
            actions.extend(self.broadcast_vertex(r))
        }
        actions
    }

    fn broadcast_vertex(&mut self, r: ViewNumber) -> Vec<Action> {
        trace!(id = %self.public_key, current = %self.round, %r, "broadcast_vertex");
        let mut actions = Vec::new();
        let v = self.create_new_vertex(r);
        if let Ok(a) = self.try_to_add_to_dag(v.clone()) {
            actions.extend(a)
        }
        let e = Envelope::signed(v, &self.private_key, self.public_key);
        actions.push(Action::SendProposal(e));
        actions
    }

    fn create_new_vertex(&mut self, r: ViewNumber) -> Vertex {
        trace!(id = %self.public_key, current = %self.round, %r, "create_new_vertex");
        let leader = self.committee.leader(r - 1);
        let mut prev = self.dag.vertices(r - 1);
        let mut new = Vertex::new(r, self.public_key);
        new.set_block(self.blocks.pop_front().unwrap_or_default());
        new.add_strong_edges(prev.clone().map(Vertex::id).cloned());
        for r in (1 .. r.u64() - 1).rev() {
            for v in self.dag.vertices(ViewNumber::new(r)) {
                if !self.dag.is_connected(&new, v, false) {
                    new.add_weak_edge(v.id().clone());
                }
            }
        }
        if !prev.any(|v| v.id().source() == &leader) {
            let t = self.timeouts
                .get_mut(&(r - 1))
                .expect("no leader vertex => timeout cert")
                .certificate()
                .expect("> 2f timeouts");
            new.set_timeout(t.clone());
            if self.public_key != leader {
                let n = self.no_votes.certificate().expect("> 2f no-votes");
                new.set_no_vote(n.clone());
            }
        }
        new
    }

    fn try_to_add_to_dag(&mut self, v: Vertex) -> Result<Vec<Action>, ()> {
        if v.strong_edges().chain(v.weak_edges()).all(|id| self.dag.vertex(id.round(), id.source()).is_some()) {
            let r = v.id().round();
            self.buffer.remove(&v);
            self.dag.add(v);
            if self.dag.vertices(r).count() as u64 > self.committee.success_threshold().get() {
                let Some(v) = self.leader_vertex(r - 1).cloned() else {
                    return Ok(Vec::new())
                };
                if self.dag.vertices(r).filter(|w| self.dag.is_connected(w, &v, true)).count() as u64 > self.committee.success_threshold().get() {
                    return Ok(self.commit_leader(v))
                }
            }
            return Ok(Vec::new())
        }
        Err(())
    }

    fn commit_leader(&mut self, mut v: Vertex) -> Vec<Action> {
        self.leader_stack.push(v.clone());
        for r in ((self.committed_round + 1).u64() .. v.id().round().u64()).rev() {
            let Some(l) = self.leader_vertex(ViewNumber::new(r)).cloned() else {
                continue // Is this correct?
            };
            if self.dag.is_connected(&v, &l, true) {
                self.leader_stack.push(l.clone());
                v = l
            }
        }
        self.committed_round = v.id().round();
        self.order_vertices()
    }

    fn order_vertices(&mut self) -> Vec<Action> {
        let mut delivered = std::mem::take(&mut self.delivered);
        let mut actions = Vec::new();
        while let Some(v) = self.leader_stack.pop() {
            for to_deliver in self.dag.all_vertices().skip(1).filter(|w| self.dag.is_connected(&v, w, false)) {
                if delivered.contains(to_deliver) {
                    continue
                }
                actions.push(Action::Deliver(to_deliver.block().clone(), to_deliver.id().round(), *to_deliver.id().source()));
                delivered.insert(to_deliver.clone());
            }
        }
        self.delivered = delivered;
        actions
    }

    fn is_valid(&self, v: &Vertex) -> bool {
        trace!(id = %self.public_key, current = %self.round, v = %v.id(), "is_valid");
        let Some(l) = self.leader_vertex(v.id().round() - 1) else {
            warn!(v = %v.id(), "no leader vertex for prior round found");
            return false
        };
        if v.has_strong_edge(l.id()) {
            return true
        }
        if let Some(cert) = v.timeout_cert() {
            if !cert.is_valid_quorum(&self.committee) {
                warn!(v = %v.id(), "has timeout certificate with invalid quorum");
                return false
            }
        }
        if v.id().source() != &self.committee.leader(v.id().round()) {
            return true
        }
        if let Some(cert) = v.no_vote_cert() {
            if !cert.is_valid_quorum(&self.committee) {
                warn!(v = %v.id(), "has no-vote certificate with invalid quorum");
                return false
            }
        }
        true
    }

    fn leader_vertex(&self, r: ViewNumber) -> Option<&Vertex> {
        self.dag.vertex(r, &self.committee.leader(r))
    }
}
