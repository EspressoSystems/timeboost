use std::collections::{BTreeMap, HashSet};
use std::mem;
use std::num::NonZeroUsize;

use timeboost_core::types::{
    block::Block,
    certificate::{self_certificate, Certificate},
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    message::{Action, Evidence, Message, NoVote, NoVoteMessage, Timeout, TimeoutMessage},
    round_number::RoundNumber,
    transaction::TransactionsQueue,
    vertex::Vertex,
    Keypair, NodeId, PublicKey,
};
use tracing::{debug, error, info, instrument, trace, warn};

mod dag;
mod vote;

pub use dag::Dag;
pub use vote::VoteAccumulator;

#[cfg(feature = "metrics")]
mod metrics;

#[cfg(feature = "metrics")]
pub use metrics::ConsensusMetrics;

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

    /// The set of round number confirmations that we've received so far per round.
    rounds: BTreeMap<RoundNumber, VoteAccumulator<RoundNumber>>,

    /// The set of timeouts that we've received so far per round.
    timeouts: BTreeMap<RoundNumber, VoteAccumulator<Timeout>>,

    /// The set of no votes that we've received so far.
    no_votes: VoteAccumulator<NoVote>,

    /// Stack of leader vertices.
    leader_stack: Vec<Vertex>,

    /// Transactions to include in vertex proposals.
    transactions: TransactionsQueue,

    #[cfg(feature = "metrics")]
    metrics: std::sync::Arc<ConsensusMetrics>,

    #[cfg(feature = "metrics")]
    timer: std::time::Instant,
}

impl Consensus {
    pub fn new(id: NodeId, keypair: Keypair, committee: StaticCommittee) -> Self {
        Self {
            id,
            keypair,
            dag: Dag::new(committee.size()),
            round: RoundNumber::genesis(),
            committed_round: RoundNumber::genesis(),
            buffer: HashSet::new(),
            delivered: HashSet::new(),
            rounds: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            no_votes: VoteAccumulator::new(committee.clone()),
            committee,
            leader_stack: Vec::new(),
            transactions: TransactionsQueue::new(),
            #[cfg(feature = "metrics")]
            metrics: std::sync::Arc::new(ConsensusMetrics::default()),
            #[cfg(feature = "metrics")]
            timer: std::time::Instant::now(),
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

    #[cfg(feature = "metrics")]
    pub fn set_metrics<M>(&mut self, m: std::sync::Arc<ConsensusMetrics>) {
        self.metrics = m
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
            let vtx = Vertex::new(r, self_certificate(r, &self.keypair), &self.keypair);
            let env = Envelope::signed(vtx, &self.keypair);
            return vec![Action::SendProposal(env)];
        }

        let Some(e) = self.evidence(r) else {
            error!(
                node  = %self.id,
                round = %self.round,
                "no evidence for round exists"
            );
            return Vec::new();
        };

        self.advance_from_round(r, e)
    }

    /// Main entry point to process a `Message`.
    #[instrument(level = "trace", skip_all, fields(
        node      = %self.id,
        round     = %self.round,
        committed = %self.committed_round,
        buffered  = %self.buffer.len(),
        delivered = %self.delivered.len(),
        leaders   = %self.leader_stack.len(),
        rounds    = %self.rounds.len(),
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
        if let Some(e) = self.evidence(r - 1) {
            let t = TimeoutMessage::new(r, e, &self.keypair);
            let e = Envelope::signed(t, &self.keypair);
            return vec![Action::SendTimeout(e)];
        }
        error!(
            node   = %self.id,
            round  = %self.round,
            "no evidence for round - 1 exists"
        );
        Vec::new()
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
        vround = %e.data().round().data())
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
                vround = %vertex.round().data(),
                "vertex already in dag"
            );
            return actions;
        }

        if !self.is_valid(&vertex) {
            return actions;
        }

        let accum = self
            .rounds
            .entry(*vertex.round().data())
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        if let Err(err) = accum.add(vertex.round().clone()) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %vertex.round().data(),
                err    = %err,
                "failed to add round to evidence"
            );
            if accum.is_empty() {
                self.rounds.remove(vertex.round().data());
            }
            return actions;
        }

        match self.try_to_add_to_dag(&vertex) {
            Err(()) => {
                self.buffer.insert(vertex);
                #[cfg(feature = "metrics")]
                self.metrics.vertex_buffer.set(self.buffer.len())
            }
            Ok(a) => {
                actions.extend(a);

                // Since we managed to add another vertex, try to add all buffered vertices to
                // the DAG too:
                let buffer = mem::take(&mut self.buffer);
                let mut retained = HashSet::new();
                for w in buffer
                    .into_iter()
                    .filter(|w| w.round().data() <= vertex.round().data())
                {
                    if let Ok(b) = self.try_to_add_to_dag(&w) {
                        actions.extend(b)
                    } else {
                        retained.insert(w);
                    }
                }
                debug_assert!(self.buffer.is_empty());
                self.buffer = retained;

                #[cfg(feature = "metrics")]
                self.metrics.vertex_buffer.set(self.buffer.len());

                // Check if we can advance to the next round.

                if *vertex.round().data() < self.round {
                    return actions;
                }

                if (self.dag.vertex_count(*vertex.round().data()) as u64)
                    < self.committee.quorum_size().get()
                {
                    return actions;
                }

                if let Some(e) = self.evidence(*vertex.round().data()) {
                    actions.extend(self.advance_from_round(*vertex.round().data(), e))
                } else {
                    error!(
                        node   = %self.id,
                        round  = %self.round,
                        vround = %vertex.round().data(),
                        "no evidence for vertex round exists outside of dag"
                    )
                }
            }
        }

        actions
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.id, round = %self.round))]
    pub fn handle_no_vote(&mut self, e: Envelope<NoVoteMessage, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        if e.data().round().signing_key() != e.signing_key() {
            warn!(
                src = %e.data().round().signing_key(),
                sig = %e.signing_key(),
                "no-vote sender != signer"
            );
            return actions;
        }

        if !e.data().round().is_valid(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                source = %e.signing_key(),
                "no-vote round signature is not valid"
            );
            return actions;
        }

        if !e.data().evidence().is_valid_quorum(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                source = %e.signing_key(),
                "no-vote has invalid evidence quorum"
            );
            return actions;
        }

        if e.data().evidence().round() + 1 != **e.data().round().data() {
            warn!(
                node   = %self.id,
                round  = %self.round,
                source = %e.signing_key(),
                "no-vote evidence applies to wrong round"
            );
            return actions;
        }

        let timeout_round = **e.data().round().data();

        if timeout_round < self.round {
            debug!(
                node  = %self.id,
                round = %self.round,
                r     = %timeout_round,
                "ignoring old no vote"
            );
            return actions;
        }

        // Here the no-vote is sent from round r - 1 to leader in round r that is why we add 1 to
        // round to get correct leader
        if *self.public_key() != self.committee.leader(timeout_round + 1) {
            warn!(
                node  = %self.id,
                round = %self.round,
                r     = %timeout_round,
                "received no vote for round in which we are not the leader"
            );
            return actions;
        }

        let (no_vote, evidence) = e.into_data().into_parts();

        let tc = match evidence {
            Evidence::Timeout(c) => c,
            Evidence::Regular(_) => {
                warn!(
                    node  = %self.id,
                    round = %self.round,
                    r     = %timeout_round,
                    "received no vote without evidence for timeout"
                );
                return actions;
            }
        };

        if !self.has_timeout_cert(**tc.data()) {
            self.timeouts
                .entry(**tc.data())
                .or_insert_with(|| VoteAccumulator::new(self.committee.clone()))
                .set_certificate(tc.clone())
        }

        match self.no_votes.add(no_vote) {
            // Not enough votes yet.
            Ok(None) =>
            {
                #[cfg(feature = "metrics")]
                self.metrics.no_votes.set(self.no_votes.votes())
            }
            // Certificate is formed when we have 2f + 1 votes added to accumulator.
            Ok(Some(nc)) => {
                // We need to reset round timer and broadcast vertex with timeout certificate and
                // no-vote certificate.
                let nc = nc.clone();
                actions.extend(self.advance_leader_with_no_vote_certificate(timeout_round, tc, nc));
            }
            Err(e) => warn!(
                node  = %self.id,
                round = %self.round,
                r     = %timeout_round,
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
    pub fn handle_timeout(&mut self, e: Envelope<TimeoutMessage, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        if e.data().round().signing_key() != e.signing_key() {
            warn!(
                src = %e.data().round().signing_key(),
                sig = %e.signing_key(),
                "timeout sender != signer"
            );
            return actions;
        }

        if !e.data().round().is_valid(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                source = %e.signing_key(),
                "timeout message round signature is not valid"
            );
            return actions;
        }

        if !e.data().evidence().is_valid_quorum(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                source = %e.signing_key(),
                "timeout message has invalid evidence quorum"
            );
            return actions;
        }

        if e.data().evidence().round() + 1 != **e.data().round().data() {
            warn!(
                node   = %self.id,
                round  = %self.round,
                source = %e.signing_key(),
                "timeout message evidence applies to wrong round"
            );
            return actions;
        }

        let timeout_round = **e.data().round().data();

        if timeout_round < self.round {
            debug!(
                node  = %self.id,
                round = %self.round,
                r     = %timeout_round,
                "ignoring old timeout"
            );
            return actions;
        }

        let (timeout, evidence) = e.into_data().into_parts();

        let accum = self
            .timeouts
            .entry(timeout_round)
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        if let Err(err) = accum.add(timeout) {
            warn!(
                node  = %self.id,
                round = %self.round,
                r     = %timeout_round,
                err   = %err,
                "could not add timeout round as evidence"
            );
            if accum.is_empty() {
                self.timeouts.remove(&timeout_round);
            }
            return actions;
        }

        // Have we received more than f timeouts?
        if accum.votes() as u64 == self.committee.threshold().get() + 1 {
            let t = TimeoutMessage::new(timeout_round, evidence, &self.keypair);
            let e = Envelope::signed(t, &self.keypair);
            actions.push(Action::SendTimeout(e))
        }

        // Have we received 2f + 1 timeouts?
        if accum.votes() as u64 == self.committee.quorum_size().get() {
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

        #[cfg(feature = "metrics")]
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

        let round = **cert.data();

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

        if !self.has_timeout_cert(**cert.data()) {
            self.timeouts
                .entry(**cert.data())
                .or_insert_with(|| VoteAccumulator::new(self.committee.clone()))
                .set_certificate(cert.clone())
        }

        if self.dag.vertex_count(round) as u64 >= self.committee.quorum_size().get() {
            actions.extend(self.advance_from_round(round, cert.into()));
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
    fn advance_from_round(&mut self, round: RoundNumber, evidence: Evidence) -> Vec<Action> {
        let mut actions = Vec::new();

        // With a leader vertex we can move on to the next round immediately.
        if self.leader_vertex(round).is_some() {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let v = self.create_new_vertex(self.round, evidence);
            actions.extend(self.add_and_broadcast_vertex(v.0));
            self.clear_aggregators(self.round);
            #[cfg(feature = "metrics")]
            {
                self.metrics
                    .round_duration
                    .add_point(self.timer.elapsed().as_secs_f64());
                self.timer = std::time::Instant::now();
                self.metrics.round.set(*self.round as usize);
            }
            return actions;
        }

        // Otherwise check that we have a timeout certificate as evidence:
        let Some(tc) = self.timeout_cert(round) else {
            return actions;
        };

        // We inform the leader of the next round that we did not vote in the previous round.
        let env = Envelope::signed(
            NoVoteMessage::new(round, tc.clone(), &self.keypair),
            &self.keypair,
        );
        let leader = self.committee.leader(round + 1);
        actions.push(Action::SendNoVote(leader, env));

        // If we are not ourselves leader of the next round we can move to it directly.
        if *self.public_key() != leader {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let NewVertex(v) = self.create_new_vertex(self.round, tc.into());
            debug_assert!(v.evidence().is_timeout());
            actions.extend(self.add_and_broadcast_vertex(v));
            self.clear_aggregators(self.round);
            #[cfg(feature = "metrics")]
            {
                self.metrics
                    .round_duration
                    .add_point(self.timer.elapsed().as_secs_f64());
                self.timer = std::time::Instant::now();
                self.metrics.round.set(*self.round as usize);
            }
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

    #[instrument(level = "trace", skip(self, nc), fields(node = %self.id, round = %self.round))]
    fn advance_leader_with_no_vote_certificate(
        &mut self,
        round: RoundNumber,
        tc: Certificate<Timeout>,
        nc: Certificate<NoVote>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        self.round = round + 1;
        actions.push(Action::ResetTimer(self.round));
        let NewVertex(mut v) = self.create_new_vertex(self.round, tc.into());
        v.set_no_vote(nc);
        actions.extend(self.add_and_broadcast_vertex(v));
        self.clear_aggregators(self.round);
        self.no_votes.clear();
        #[cfg(feature = "metrics")]
        {
            self.metrics
                .round_duration
                .add_point(self.timer.elapsed().as_secs_f64());
            self.timer = std::time::Instant::now();
            self.metrics.no_votes.set(0);
            self.metrics.round.set(*self.round as usize);
        }
        actions
    }

    /// Add a new vertex to the DAG and send it as a proposal to nodes.
    #[instrument(level = "trace", skip_all, fields(
        node   = %self.id,
        round  = %self.round,
        vround = %v.round().data())
    )]
    fn add_and_broadcast_vertex(&mut self, v: Vertex) -> Vec<Action> {
        self.dag.add(v.clone());
        #[cfg(feature = "metrics")]
        self.metrics.dag_depth.set(self.dag.depth());
        let mut actions = Vec::new();
        let e = Envelope::signed(v, &self.keypair);
        actions.push(Action::SendProposal(e));
        actions
    }

    /// Create a new vertex for the given round `r`.
    ///
    /// NB that the returned value requires further processing iff there is no
    /// leader vertex in `r - 1`. In that case a no-vote certificate may be required.
    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn create_new_vertex(&mut self, r: RoundNumber, e: Evidence) -> NewVertex {
        let previous = self.dag.vertices(r - 1);

        let mut new = Vertex::new(r, e, &self.keypair);
        new.set_block(Block::new().with_transactions(self.transactions.take()));
        new.add_edges(previous.map(Vertex::source).cloned());

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
        vround = %v.round().data())
    )]
    fn try_to_add_to_dag(&mut self, v: &Vertex) -> Result<Vec<Action>, ()> {
        let round = *v.round().data();

        if !v.edges().all(|w| self.dag.vertex(round - 1, w).is_some()) {
            debug!(
                node   = %self.id,
                round  = %self.round,
                vround = %round,
                "not all edges are resolved in dag"
            );
            return Err(());
        }

        self.dag.add(v.clone());

        #[cfg(feature = "metrics")]
        self.metrics.dag_depth.set(self.dag.depth());

        if self.dag.vertex_count(round) as u64 >= self.committee.quorum_size().get() {
            // We have enough vertices => try to commit the leader vertex:
            let Some(l) = self.leader_vertex(round - 1).cloned() else {
                debug!(
                    node   = %self.id,
                    round  = %self.round,
                    vround = %round,
                    "no leader vertex in vround - 1 => can not commit"
                );
                return Ok(Vec::new());
            };
            // If enough edges to the leader of the previous round exist we can commit the
            // leader vertex.
            if self
                .dag
                .vertices(round)
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
        vround = %v.round().data())
    )]
    fn commit_leader(&mut self, mut v: Vertex) -> Vec<Action> {
        self.leader_stack.push(v.clone());
        for r in (*self.committed_round + 1..**v.round().data()).rev() {
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
        self.committed_round = *v.round().data();
        trace!(commit = %self.committed_round, "committed round");
        #[cfg(feature = "metrics")]
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
                let r = *to_deliver.round().data();
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
        self.delivered.retain(|v| *v.round().data() >= r);
        self.buffer.retain(|v| *v.round().data() >= r);

        #[cfg(feature = "metrics")]
        {
            self.metrics.dag_depth.set(self.dag.depth());
            self.metrics.vertex_buffer.set(self.buffer.len());
            self.metrics.delivered.set(self.delivered.len());
        }
    }

    /// Remove timeout and round vote aggregators up to the given round.
    #[instrument(level = "trace", skip(self), fields(node = %self.id, round = %self.round))]
    fn clear_aggregators(&mut self, to: RoundNumber) {
        self.rounds = self.rounds.split_off(&to);
        self.timeouts = self.timeouts.split_off(&to);
        #[cfg(feature = "metrics")]
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
        vround = %v.round().data())
    )]
    fn is_valid(&self, v: &Vertex) -> bool {
        if !v.round().is_valid(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
                vsrc   = %v.source(),
                "vertex round signature is not valid"
            );
            return false;
        }

        if v.is_genesis() {
            info!(
                node   = %self.id,
                round  = %self.round,
                source = %v.source(),
                "accepting genesis vertex"
            );
            return true;
        }

        if !v.evidence().is_valid_quorum(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
                vsrc   = %v.source(),
                "vertex has invalid round evidence quorum"
            );
            return false;
        }

        if v.evidence().round() + 1 != *v.round().data() {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
                vsrc   = %v.source(),
                "vertex round evidence applies to wrong round"
            );
            return false;
        }

        if (v.num_edges() as u64) < self.committee.quorum_size().get() {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
                vsrc   = %v.source(),
                "vertex has not enough edges"
            );
            return false;
        }

        if self.committed_round > 2.into() && *v.round().data() < self.committed_round - 2 {
            debug!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
                vsrc   = %v.source(),
                "vertex round is too old"
            );
            return false;
        }

        if v.has_edge(&self.committee.leader(*v.round().data() - 1)) {
            return true;
        }

        if v.source() != &self.committee.leader(*v.round().data()) {
            return true;
        }

        let Some(ncert) = v.no_vote_cert() else {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
                vsrc   = %v.source(),
                "vertex is missing no-vote certificate"
            );
            return false;
        };

        if **ncert.data() != *v.round().data() - 1 {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
                vsrc   = %v.source(),
                "vertex has no-vote certificate from invalid round"
            );
            return false;
        }

        if !ncert.is_valid_quorum(&self.committee) {
            warn!(
                node   = %self.id,
                round  = %self.round,
                vround = %v.round().data(),
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

    fn evidence(&self, r: RoundNumber) -> Option<Evidence> {
        if let Some(cert) = self.rounds.get(&r).and_then(|a| a.certificate()) {
            return Some(Evidence::Regular(cert.clone()));
        }
        if let Some(cert) = self.timeouts.get(&r).and_then(|a| a.certificate()) {
            return Some(Evidence::Timeout(cert.clone()));
        }
        None
    }

    fn timeout_cert(&self, r: RoundNumber) -> Option<Certificate<Timeout>> {
        self.timeouts.get(&r)?.certificate().cloned()
    }

    fn has_timeout_cert(&self, r: RoundNumber) -> bool {
        self.timeouts
            .get(&r)
            .map(|a| a.certificate().is_some())
            .unwrap_or(false)
    }
}

#[cfg(feature = "test")]
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
