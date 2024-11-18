use std::collections::{BTreeMap, HashSet};
use std::mem;
use std::num::NonZeroUsize;
use std::sync::Arc;

use timeboost_core::types::{
    block::Block,
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    message::{Action, Message, NoVote, Timeout},
    metrics::ConsensusMetrics,
    round_number::RoundNumber,
    transaction::TransactionsQueue,
    vertex::Vertex,
    Keypair, NodeId, PublicKey,
};
use tracing::{debug, error, instrument, trace, warn};

mod dag;
mod vote;

pub use dag::Dag;
pub use vote::VoteAccumulator;

/// A `NewVertex` may need to have a timeout or no-vote certificate set.
struct NewVertex(Vertex);

pub struct Consensus {
    /// The ID of the node running this consensus instance.
    id: NodeId,

    /// The public and private key of this node.
    keypair: Keypair,

    /// The DAG of vertices
    dag: Dag,

    /// The quorum membership.
    committee: StaticCommittee,

    /// The current round number.
    round: RoundNumber,

    /// The last committed round number.
    committed_round: RoundNumber,

    /// The set of vertices that we've received so far.
    buffer: HashSet<Vertex>,

    /// The set of vertices that we've delivered so far.
    delivered: HashSet<Vertex>,

    /// The set of timeouts that we've received so far per round.
    timeouts: BTreeMap<RoundNumber, VoteAccumulator<Timeout>>,

    /// The set of no votes that we've received so far.
    no_votes: VoteAccumulator<NoVote>,

    /// Stack of leader vertices.
    leader_stack: Vec<Vertex>,

    /// Transactions to include in vertex proposals.
    transactions: TransactionsQueue,

    /// The consensus metrics for this node.
    metrics: Arc<ConsensusMetrics>,

    /// The timer for recording metrics related to duration of consensus operations.
    metrics_timer: std::time::Instant,
}

impl Consensus {
    pub fn new(
        id: NodeId,
        keypair: Keypair,
        committee: StaticCommittee,
        metrics: Arc<ConsensusMetrics>,
    ) -> Self {
        Self {
            id,
            keypair,
            dag: Dag::new(committee.size()),
            round: RoundNumber::genesis(),
            committed_round: RoundNumber::genesis(),
            buffer: HashSet::new(),
            delivered: HashSet::new(),
            timeouts: BTreeMap::new(),
            no_votes: VoteAccumulator::new(committee.clone()),
            committee,
            leader_stack: Vec::new(),
            transactions: TransactionsQueue::new(),
            metrics,
            metrics_timer: std::time::Instant::now(),
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn committee_size(&self) -> NonZeroUsize {
        self.committee.size()
    }

    pub fn set_transactions_queue(&mut self, q: TransactionsQueue) {
        self.transactions = q
    }

    /// (Re-)start consensus.
    ///
    /// This continues with the highest round number found in the DAG (or else
    /// starts from the genesis round).
    #[instrument(level="info", skip_all, fields(id = %self.id, round = %self.round))]
    pub fn go(&mut self, d: Dag) -> Vec<Action> {
        let r = d.max_round().unwrap_or(RoundNumber::genesis());

        self.dag = d;
        self.round = r;
        // TODO: Save and restore other states (committed_round, buffer, etc.)

        if r == RoundNumber::genesis() {
            for p in self.committee.committee() {
                self.dag.add(Vertex::new(r, *p))
            }
        }

        self.advance_from_round(r)
    }

    /// Main entry point to process a `Message`.
    #[instrument(level = "trace", skip_all, fields(
        node      = %self.id,
        round     = %self.round,
        committed = %self.committed_round,
        buffered  = %self.buffer.len(),
        delivered = %self.delivered.len(),
        leaders   = %self.leader_stack.len(),
        timeouts  = %self.timeouts.len(),
        dag       = %self.dag.depth())
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

    /// An internal timeout occurred.
    ///
    /// This means we did not receive a leader vertex in a round and
    /// results in a timeout message being broadcasted to all nodes.
    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    pub fn timeout(&mut self, r: RoundNumber) -> Vec<Action> {
        debug_assert_eq!(r, self.round);
        debug_assert!(self.leader_vertex(r).is_none());
        let e = Envelope::signed(Timeout::new(r), &self.keypair);
        vec![Action::SendTimeout(e)]
    }

    /// Handle a vertex proposal of some node.
    ///
    /// We validate the vertex and try to add it to our DAG. If the vertex is valid
    /// but we can not yet add it (e.g. because not all of its edges resolve to other
    /// DAG elements yet), we store it in a buffer and retry adding it once we have
    /// received another vertex which we sucessfully added.
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

        if self.dag.contains(&vertex) {
            debug!(
                node   = %self.id,
                round  = %self.round,
                ours   = %(self.public_key() == vertex.source()),
                vround = %vertex.round(),
                "vertex already in dag"
            );
            return actions;
        }

        if !self.is_valid(&vertex) {
            return actions;
        }

        match self.try_to_add_to_dag(&vertex) {
            Err(()) => {
                self.buffer.insert(vertex);
                self.metrics.vertex_buffer.set(self.buffer.len())
            }
            Ok(a) => {
                actions.extend(a);

                // Since we managed to add another vertex, try to add all buffered vertices to
                // the DAG too:
                let buffer = mem::take(&mut self.buffer);
                let mut retained = HashSet::new();
                for w in buffer.into_iter() {
                    if w.round() > vertex.round() {
                        retained.insert(w);
                        continue;
                    }
                    if let Ok(b) = self.try_to_add_to_dag(&w) {
                        actions.extend(b)
                    } else {
                        retained.insert(w);
                    }
                }
                debug_assert!(self.buffer.is_empty());
                self.buffer = retained;

                self.metrics.vertex_buffer.set(self.buffer.len());

                // Check if we can advance to the next round.

                if vertex.round() < self.round {
                    return actions;
                }

                if (self.dag.vertex_count(vertex.round()) as u64)
                    < self.committee.quorum_size().get()
                {
                    return actions;
                }

                actions.extend(self.advance_from_round(vertex.round()));
            }
        }

        actions
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    pub fn handle_no_vote(&mut self, e: Envelope<NoVote, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();
        let round = e.data().round();

        if round < self.round {
            debug!(
                node  = %self.id,
                round = %self.round,
                r     = %round,
                "ignoring old no vote"
            );
            return actions;
        }

        // Here the no-vote is sent from round r - 1 to leader in round r that is why we add 1 to
        // round to get correct leader
        if *self.public_key() != self.committee.leader(round + 1) {
            warn!(
                node  = %self.id,
                round = %self.round,
                r     = %round,
                "received no vote for round in which we are not the leader"
            );
            return actions;
        }

        match self.no_votes.add(e) {
            // Not enough votes yet.
            Ok(None) => self.metrics.no_votes.set(self.no_votes.votes()),
            // Certificate is formed when we have 2f + 1 votes added to accumulator.
            Ok(Some(nc)) => {
                // We need to reset round timer and broadcast vertex with timeout certificate and
                // no-vote certificate.
                let Some(tc) = self
                    .timeouts
                    .get_mut(&round)
                    .and_then(|t| t.certificate())
                    .cloned()
                else {
                    self.metrics.no_votes.set(self.no_votes.votes());
                    warn!(
                        node  = %self.id,
                        round = %self.round,
                        r     = %round,
                        "leader received 2f + 1 no votes, but has no timeout certificate for the round"
                    );
                    return actions;
                };
                let nc = nc.clone();
                actions.extend(self.advance_leader_with_no_vote_certificate(round, tc, nc));
            }
            Err(e) => warn!(
                node  = %self.id,
                round = %self.round,
                r     = %round,
                err   = %e,
                "could not add no vote certificate to vote accumulator"
            ),
        }

        actions
    }

    /// Handle a timeout message of some node.
    ///
    /// Once we have collected more than f timeouts we start broadcasting our own timeout.
    /// Eventually, if we receive more than 2f timeouts we form a timeout certificate and
    /// broadcast that too.
    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    pub fn handle_timeout(&mut self, e: Envelope<Timeout, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        let round = e.data().round();

        if round < self.round {
            debug!(
                node  = %self.id,
                round = %self.round,
                r     = %round,
                "ignoring old timeout"
            );
            return actions;
        }

        let accum = self
            .timeouts
            .entry(round)
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        let votes = accum.votes();

        if let Err(e) = accum.add(e) {
            warn!(
                node  = %self.id,
                round = %self.round,
                r     = %round,
                err   = %e,
                "could not add timeout to vote accumulator"
            );
            if accum.is_empty() {
                // Remove newly created accumulator because the vote that triggered its
                // creation was rejected.
                self.timeouts.remove(&round);
            }
            return actions;
        }

        // Have we received more than f timeouts?
        if votes != accum.votes() && accum.votes() as u64 == self.committee.threshold().get() + 1 {
            let e = Envelope::signed(Timeout::new(round), &self.keypair);
            actions.push(Action::SendTimeout(e))
        }

        // Have we received 2f + 1 timeouts?
        if votes != accum.votes() && accum.votes() as u64 == self.committee.quorum_size().get() {
            if let Some(cert) = accum.certificate() {
                actions.push(Action::SendTimeoutCert(cert.clone()))
            } else {
                error!(
                    node  = %self.id,
                    round = %self.round,
                    "no timeout certificate despite enough votes"
                );
            }
        }

        self.metrics.timeout_buffer.set(self.timeouts.len());

        actions
    }

    /// Handle a timeout certificate, representing more than 2f timeouts.
    ///
    /// If we also have more than 2f vertex proposals (i.e. we are just missing the
    /// leader vertex), we can move to the next round and include the certificate in
    /// our next vertex proposal.
    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    pub fn handle_timeout_cert(&mut self, cert: Certificate<Timeout>) -> Vec<Action> {
        let mut actions = Vec::new();

        let round = cert.data().round();

        if round < self.round {
            debug!(
                node  = %self.id,
                round = %self.round,
                r     = %round,
                "ignoring old timeout certificate"
            );
            return actions;
        }

        if !cert.is_valid_quorum(&self.committee) {
            warn!(
                node  = %self.id,
                round = %self.round,
                r     = %round,
                "received invalid certificate"
            );
            return actions;
        }

        if self.dag.vertex_count(round) as u64 >= self.committee.quorum_size().get() {
            actions.extend(self.advance_from_round(round));
        }

        actions
    }

    /// Try to advance from the given round `r` to `r + 1`.
    ///
    /// We can only advance to the next round if
    ///
    ///   1. we have a leader vertex in `r`, or else
    ///   2. we have a timeout certificate for `r`, and,
    ///   3. if we are leader of `r + 1`, we have a no-vote certificate for `r`.
    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn advance_from_round(&mut self, round: RoundNumber) -> Vec<Action> {
        let mut actions = Vec::new();

        // With a leader vertex we can move on to the next round immediately.
        if self.leader_vertex(round).is_some() {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let v = self.create_new_vertex(self.round);
            actions.extend(self.add_and_broadcast_vertex(v.0));
            self.clear_timeout_aggregators(self.round);
            self.metrics
                .round_duration
                .add_point(self.metrics_timer.elapsed().as_secs_f64());
            self.metrics_timer = std::time::Instant::now();
            self.metrics.round.set(*self.round as usize);
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

        // We inform the leader of the next round that we did not vote in the previous round.
        let env = Envelope::signed(NoVote::new(round), &self.keypair);
        let leader = self.committee.leader(round + 1);
        actions.push(Action::SendNoVote(leader, env));

        // If we are not ourselves leader of the next round we can move to it directly.
        if *self.public_key() != leader {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let NewVertex(mut v) = self.create_new_vertex(self.round);
            v.set_timeout(tc);
            actions.extend(self.add_and_broadcast_vertex(v));
            self.clear_timeout_aggregators(self.round);

            // Update the metrics
            self.metrics
                .round_duration
                .add_point(self.metrics_timer.elapsed().as_secs_f64());
            self.metrics_timer = std::time::Instant::now();
            self.metrics.round.set(*self.round as usize);

            return actions;
        }

        // As leader of the next round we need to wait for > 2f no-votes of the current round
        // since we have no leader vertex.
        let Some(nc) = self.no_votes.certificate().cloned() else {
            return actions;
        };

        actions.extend(self.advance_leader_with_no_vote_certificate(round, tc, nc));
        actions
    }

    #[instrument(level = "trace", skip(self, tc, nc), fields(node = %self.id, round = %self.round))]
    fn advance_leader_with_no_vote_certificate(
        &mut self,
        round: RoundNumber,
        tc: Certificate<Timeout>,
        nc: Certificate<NoVote>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        self.round = round + 1;
        actions.push(Action::ResetTimer(self.round));
        let NewVertex(mut v) = self.create_new_vertex(self.round);
        v.set_no_vote(nc);
        v.set_timeout(tc);
        actions.extend(self.add_and_broadcast_vertex(v));
        self.clear_timeout_aggregators(self.round);
        self.no_votes.clear();
        self.metrics
            .round_duration
            .add_point(self.metrics_timer.elapsed().as_secs_f64());
        self.metrics_timer = std::time::Instant::now();
        self.metrics.no_votes.set(0);
        self.metrics.round.set(*self.round as usize);
        actions
    }

    /// Add a new vertex to the DAG and send it as a proposal to nodes.
    #[instrument(level = "trace", skip_all, fields(
        node   = %self.id,
        round  = %self.round,
        vround = %v.round())
    )]
    fn add_and_broadcast_vertex(&mut self, v: Vertex) -> Vec<Action> {
        self.dag.add(v.clone());
        self.metrics.dag_depth.set(self.dag.depth());
        let mut actions = Vec::new();
        let e = Envelope::signed(v, &self.keypair);
        actions.push(Action::SendProposal(e));
        actions
    }

    /// Create a new vertex for the given round `r`.
    ///
    /// NB that the returned value requires further processing iff there is no
    /// leader vertex in `r - 1`. In that case a timeout certificate (and potentially
    /// a no-vote certificate) is required.
    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn create_new_vertex(&mut self, r: RoundNumber) -> NewVertex {
        let prev = self.dag.vertices(r - 1);

        let mut new = Vertex::new(r, *self.public_key());
        new.set_block(Block::new().with_transactions(self.transactions.take()));
        new.add_edges(prev.map(Vertex::source).cloned());

        // Every vertex in our DAG has > 2f edges to the previous round:
        debug_assert!(new.num_edges() as u64 >= self.committee.quorum_size().get());

        NewVertex(new)
    }

    /// Try to add a vertex to the DAG.
    ///
    /// If all edges of the vertex point to other vertices in the DAG we add the
    /// vertex to the DAG. If we also have more than 2f vertices for the given
    /// round, we can try to commit the leader vertex of a round.
    #[instrument(level = "trace", skip_all, fields(
        node   = %self.id,
        round  = %self.round,
        vround = %v.round())
    )]
    fn try_to_add_to_dag(&mut self, v: &Vertex) -> Result<Vec<Action>, ()> {
        if !v
            .edges()
            .all(|w| self.dag.vertex(v.round() - 1, w).is_some())
        {
            debug!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                "not all edges are resolved in dag"
            );
            return Err(());
        }

        self.dag.add(v.clone());

        self.metrics.dag_depth.set(self.dag.depth());

        if self.dag.vertex_count(v.round()) as u64 >= self.committee.quorum_size().get() {
            // We have enough vertices => try to commit the leader vertex:
            let Some(l) = self.leader_vertex(v.round() - 1).cloned() else {
                debug!(
                    node   = %self.id,
                    round  = %self.round,
                    vround = %v.round(),
                    "no leader vertex in vround - 1 => can not commit"
                );
                return Ok(Vec::new());
            };
            // If enough edges to the leader of the previous round exist we can commit the
            // leader vertex.
            if self
                .dag
                .vertices(v.round())
                .filter(|v| v.has_edge(l.source()))
                .count() as u64
                >= self.committee.quorum_size().get()
            {
                return Ok(self.commit_leader(l));
            }
        }

        Ok(Vec::new())
    }

    /// Commit a leader vertex.
    ///
    /// Leader vertices are organised in a stack, with other vertices of a round
    /// ordered relative to them (cf. `order_vertices`).
    ///
    /// In addition to committing the argument vertex, this will also commit leader
    /// vertices between the last previously committed leader vertex and the current
    /// leader vertex, if there is a path between them.
    #[instrument(level = "trace", skip_all, fields(
        node   = %self.id,
        round  = %self.round,
        vround = %v.round())
    )]
    fn commit_leader(&mut self, mut v: Vertex) -> Vec<Action> {
        self.leader_stack.push(v.clone());
        for r in (*self.committed_round + 1..*v.round()).rev() {
            let Some(l) = self.leader_vertex(RoundNumber::new(r)).cloned() else {
                debug! {
                    node   = %self.id,
                    round  = %self.round,
                    r      = %r,
                    "no leader vertex in round r => can not commit"
                }
                continue;
            };
            if self.dag.is_connected(&v, &l) {
                self.leader_stack.push(l.clone());
                v = l
            }
        }
        self.committed_round = v.round();
        trace!(commit = %self.committed_round, "committed round");
        self.metrics
            .committed_round
            .set(*self.committed_round as usize);
        self.order_vertices()
    }

    /// Order vertices relative to leader vertices.
    ///
    /// Leader vertices are ordered on the leader stack. The other vertices of a round
    /// are ordered arbitrarily, but consistently, relative to the leaders.
    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    fn order_vertices(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        while let Some(v) = self.leader_stack.pop() {
            // This orders vertices by round and source.
            for to_deliver in self
                .dag
                .vertex_range(RoundNumber::genesis() + 1..)
                .filter(|w| self.dag.is_connected(&v, w))
            {
                if self.delivered.contains(to_deliver) {
                    continue;
                }
                let b = to_deliver.block().clone();
                let r = to_deliver.round();
                let s = *to_deliver.source();
                actions.push(Action::Deliver(b, r, s));
                self.delivered.insert(to_deliver.clone());
            }
        }
        self.gc(self.committed_round);
        actions
    }

    /// Cleanup the DAG and other collections.
    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn gc(&mut self, committed: RoundNumber) {
        if committed < 2.into() {
            return;
        }

        let r = committed - 2;
        self.dag.remove(r);
        self.delivered.retain(|v| v.round() >= r);
        self.buffer.retain(|v| v.round() >= r);

        self.metrics.dag_depth.set(self.dag.depth());
        self.metrics.vertex_buffer.set(self.buffer.len());
        self.metrics.delivered.set(self.delivered.len());
    }

    /// Remove timeout vote aggregators up to the given round.
    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn clear_timeout_aggregators(&mut self, to: RoundNumber) {
        self.timeouts = self.timeouts.split_off(&to);
        self.metrics.timeout_buffer.set(self.timeouts.len())
    }

    /// Validate an incoming vertex.
    ///
    /// Every vertex needs to have more than 2f edges. In addition, a
    /// vertex needs to have either a path to the leader vertex of the
    /// previous round, or a timeout certificate and (if from the leader) a
    /// no-vote certificate.
    #[instrument(level = "trace", skip_all, fields(
        node   = %self.id,
        round  = %self.round,
        vround = %v.round())
    )]
    fn is_valid(&self, v: &Vertex) -> bool {
        if (v.num_edges() as u64) < self.committee.quorum_size().get() {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex has not enough edges"
            );
            return false;
        }

        if self.committed_round > 2.into() && v.round() < self.committed_round - 2 {
            debug!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex round is too old"
            );
            return false;
        }

        if v.has_edge(&self.committee.leader(v.round() - 1)) {
            return true;
        }

        let Some(tcert) = v.timeout_cert() else {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                leader = %self.leader_vertex(v.round() - 1).is_some(),
                "vertex has no path to leader vertex and no timeout certificate"
            );
            return false;
        };

        if tcert.data().round() != v.round() - 1 {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex has timeout certificate from invalid round"
            );
            return false;
        }

        if !tcert.is_valid_quorum(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex has timeout certificate with invalid quorum"
            );
            return false;
        }

        if v.source() != &self.committee.leader(v.round()) {
            return true;
        }

        let Some(ncert) = v.no_vote_cert() else {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex is missing no-vote certificate"
            );
            return false;
        };

        if ncert.data().round() != v.round() - 1 {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex has no-vote certificate from invalid round"
            );
            return false;
        }

        if !ncert.is_valid_quorum(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round(),
                vsrc   = %v.source(),
                "vertex has no-vote certificate with invalid quorum"
            );
            return false;
        }

        true
    }

    fn leader_vertex(&self, r: RoundNumber) -> Option<&Vertex> {
        self.dag.vertex(r, &self.committee.leader(r))
    }
}

#[cfg(feature = "timeboost-testing")]
impl Consensus {
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    pub fn buffer(&self) -> &HashSet<Vertex> {
        &self.buffer
    }

    pub fn delivered(&self) -> &HashSet<Vertex> {
        &self.delivered
    }

    pub fn leader_stack(&self) -> &Vec<Vertex> {
        &self.leader_stack
    }

    pub fn committed_round(&self) -> RoundNumber {
        self.committed_round
    }

    pub fn committee(&self) -> &StaticCommittee {
        &self.committee
    }

    pub fn no_vote_accumulator(&self) -> &VoteAccumulator<NoVote> {
        &self.no_votes
    }

    pub fn timeout_accumulators(&self) -> &BTreeMap<RoundNumber, VoteAccumulator<Timeout>> {
        &self.timeouts
    }

    pub fn sign<D>(&self, d: D) -> Envelope<D, Validated>
    where
        D: committable::Committable,
    {
        Envelope::signed(d, &self.keypair)
    }
}
