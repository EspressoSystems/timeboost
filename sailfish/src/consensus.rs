use anyhow::{ensure, Result};
use std::collections::{BTreeMap, HashSet};
use std::cmp::max;
use std::num::NonZeroUsize;

use multisig::{Certificate, Committee, Envelope, Keypair, PublicKey, Validated, VoteAccumulator};
use timeboost_core::types::{
    block::sailfish::SailfishBlock,
    message::{Action, Evidence, Message, NoVote, NoVoteMessage, Timeout, TimeoutMessage},
    time::Timestamp,
    transaction::Transaction,
    transaction::TransactionsQueue,
    vertex::Vertex,
    NodeId,
};
use timeboost_utils::types::round_number::RoundNumber;
use tracing::{debug, error, info, instrument, trace, warn};

mod dag;

pub use dag::Dag;

use crate::metrics::SailfishMetrics;

/// A `NewVertex` may need to have a timeout or no-vote certificate set.
struct NewVertex(Vertex);

/// Information about a committee party.
#[derive(Default)]
struct PeerInfo {
    committed_round: RoundNumber,
}

pub struct Consensus {
    /// The ID of the node running this consensus instance.
    id: NodeId,

    /// The public and private key of this node.
    keypair: Keypair,

    /// The DAG of vertices.
    dag: Dag,

    /// The quorum membership.
    committee: Committee,

    /// The current round number.
    round: RoundNumber,

    /// The last committed round number.
    committed_round: RoundNumber,

    /// Information to keep per peer.
    peers: BTreeMap<PublicKey, PeerInfo>,

    /// The set of vertices that we've received so far.
    buffer: Dag,

    /// The set of values we have delivered so far.
    delivered: HashSet<(RoundNumber, PublicKey)>,

    /// The set of round number confirmations that we've received so far per round.
    rounds: BTreeMap<RoundNumber, VoteAccumulator<RoundNumber>>,

    /// The set of timeouts that we've received so far per round.
    timeouts: BTreeMap<RoundNumber, VoteAccumulator<Timeout>>,

    /// The set of no votes that we've received so far.
    no_votes: BTreeMap<RoundNumber, VoteAccumulator<NoVote>>,

    /// Stack of leader vertices.
    leader_stack: Vec<Vertex>,

    /// Transactions to include in vertex proposals.
    transactions: TransactionsQueue,

    /// The consensus metrics for this node.
    metrics: SailfishMetrics,

    /// The timer for recording metrics related to duration of consensus operations.
    metrics_timer: std::time::Instant,

    /// The current delayed inbox index.
    delayed_inbox_index: u64,

    /// Sign deterministically?
    deterministic: bool,
}

impl Consensus {
    pub fn new<N>(id: N, keypair: Keypair, committee: Committee) -> Self
    where
        N: Into<NodeId>,
    {
        Self {
            id: id.into(),
            keypair,
            peers: committee
                .parties()
                .map(|k| (*k, PeerInfo::default()))
                .collect(),
            dag: Dag::new(committee.size()),
            round: RoundNumber::genesis(),
            committed_round: RoundNumber::genesis(),
            buffer: Dag::new(committee.size()),
            delivered: HashSet::new(),
            rounds: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            no_votes: BTreeMap::new(),
            committee,
            leader_stack: Vec::new(),
            transactions: TransactionsQueue::new(),
            metrics: Default::default(),
            metrics_timer: std::time::Instant::now(),
            delayed_inbox_index: 0,
            deterministic: false,
        }
    }

    pub fn with_metrics(mut self, m: SailfishMetrics) -> Self {
        self.metrics = m;
        self
    }

    pub fn sign_deterministically(mut self, val: bool) -> Self {
        self.deterministic = val;
        self
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn committee_size(&self) -> NonZeroUsize {
        self.committee.size()
    }

    pub fn enqueue_transaction(&mut self, t: Transaction) {
        self.transactions.add(t);
    }

    pub fn set_transactions_queue(&mut self, q: TransactionsQueue) {
        self.transactions = q
    }

    pub fn set_delayed_inbox_index(&mut self, index: u64) -> Result<()> {
        ensure!(
            index >= self.delayed_inbox_index,
            "delayed inbox index must be >= than the current delayed inbox index"
        );
        self.delayed_inbox_index = index;

        Ok(())
    }

    /// (Re-)start consensus.
    ///
    /// This continues with the highest round number found in the DAG (or else
    /// starts from the genesis round).
    #[instrument(level="info", skip_all, fields(n = %self.public_key(), r = %self.round()))]
    pub fn go(&mut self, d: Dag, e: Evidence) -> Vec<Action> {
        let r = d.max_round().unwrap_or(RoundNumber::genesis());

        self.dag = d;
        self.round = r;

        if r.is_genesis() {
            let vtx = Vertex::new(r, Evidence::Genesis, &self.keypair, self.deterministic);
            let env = Envelope::signed(vtx, &self.keypair, self.deterministic);
            vec![Action::SendProposal(env), Action::ResetTimer(r)]
        } else {
            self.advance_from_round(r, e)
        }
    }

    /// Main entry point to process a `Message`.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        c = %self.committed_round,
        b = %self.buffer.depth(),
        d = %self.delivered.len(),
        l = %self.leader_stack.len(),
        t = %self.timeouts.len(),
        g = %self.dag.depth())
    )]
    pub fn handle_message(&mut self, m: Message<Validated>) -> Vec<Action> {
        match m {
            Message::Vertex(e) => self.handle_vertex(e),
            Message::NoVote(e) => self.handle_no_vote(e),
            Message::Timeout(e) => self.handle_timeout(e),
            Message::TimeoutCert(c) => self.handle_timeout_cert(c),
        }
    }

    /// An internal timeout occurred.
    ///
    /// This means we did not receive a leader vertex in a round and
    /// results in a timeout message being broadcasted to all nodes.
    #[instrument(level = "trace", skip_all, fields(n = %self.public_key(), r = %self.round()))]
    pub fn timeout(&mut self, r: RoundNumber) -> Vec<Action> {
        debug_assert_eq!(r, self.round());
        let e = if r.is_genesis() {
            Evidence::Genesis
        } else {
            self.evidence(r - 1)
                .expect("evidence for previous round exists")
        };
        let t = TimeoutMessage::new(e, &self.keypair, self.deterministic);
        let e = Envelope::signed(t, &self.keypair, self.deterministic);
        vec![Action::SendTimeout(e)]
    }

    /// Handle a vertex proposal of some node.
    ///
    /// We validate the vertex and try to add it to our DAG. If the vertex is valid
    /// but we can not yet add it (e.g. because not all of its edges resolve to other
    /// DAG elements yet), we store it in a buffer and retry adding it once we have
    /// received another vertex which we sucessfully added.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        v = %e.data())
    )]
    pub fn handle_vertex(&mut self, e: Envelope<Vertex, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        let v = e.into_data();

        if self.dag.contains(&v) || self.buffer.contains(&v) {
            debug!(n = %self.public_key(), r = %self.round, %v, "duplicate vertex");
            return actions;
        }

        if !self.is_valid(&v) {
            return actions;
        }

        let accum = self
            .rounds
            .entry(*v.round().data())
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        if let Err(e) = accum.add(v.round().clone()) {
            warn!(n = %self.id, r = %self.round, %v, %e, "failed to add round to evidence");
            if accum.is_empty() {
                self.rounds.remove(v.round().data());
            }
            return actions;
        }

        if let Some(info) = self.peers.get_mut(v.source()) {
            info.committed_round = max(info.committed_round, v.committed_round())
        } else {
            error!(n = %self.public_key(), k = %v.source(), "peer information not found")
        }

        let quorum = self.committee.quorum_size().get();

        let r = *v.round().data();
        match self.try_to_add_to_dag(v) {
            Err(v) => {
                self.buffer.add(v);
                self.metrics.vertex_buffer.set(self.buffer.depth());
            }
            Ok(a) => {
                actions.extend(a);
                if r >= self.round && self.dag.vertex_count(r) >= quorum {
                    if let Some(e) = self.evidence(r) {
                        actions.extend(self.advance_from_round(r, e))
                    } else {
                        warn!(
                            n = %self.public_key(),
                            r = %self.round,
                            v = %r,
                            "no evidence for vertex round exists outside of dag"
                        )
                    }
                }
                for v in self.buffer.drain().map(|(.., v)| v) {
                    let r = *v.round().data();
                    match self.try_to_add_to_dag(v) {
                        Ok(a) => {
                            actions.extend(a);
                            if r >= self.round && self.dag.vertex_count(r) >= quorum {
                                if let Some(e) = self.evidence(r) {
                                    actions.extend(self.advance_from_round(r, e))
                                } else {
                                    warn!(
                                        n = %self.public_key(),
                                        r = %self.round,
                                        v = %r,
                                        "no evidence for vertex round exists outside of dag"
                                    )
                                }
                            }
                        }
                        Err(v) => {
                            self.buffer.add(v);
                        }
                    }
                }

                self.metrics.vertex_buffer.set(self.buffer.depth());
            }
        }

        actions
    }

    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round(),
        s = %e.signing_key(),
        t = %e.data().no_vote().data().round())
    )]
    pub fn handle_no_vote(&mut self, e: Envelope<NoVoteMessage, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        let timeout_round = e.data().no_vote().data().round();

        if timeout_round < self.round {
            debug!(
                n = %self.public_key(),
                r = %self.round,
                t = %timeout_round,
                "ignoring old no-vote"
            );
            return actions;
        }

        // Here the no-vote is sent from round r - 1 to leader in round r that is why we add 1 to
        // round to get correct leader
        if self.public_key() != self.committee.leader(*timeout_round as usize + 1) {
            warn!(
                n = %self.public_key(),
                r = %self.round,
                t = %timeout_round,
                "received no vote for round in which we are not the leader"
            );
            return actions;
        }

        let (no_vote, tc) = e.into_data().into_parts();

        if !self.has_timeout_cert(timeout_round) {
            self.timeouts
                .entry(timeout_round)
                .or_insert_with(|| VoteAccumulator::new(self.committee.clone()))
                .set_certificate(tc.clone())
        }

        let accum = self
            .no_votes
            .entry(timeout_round)
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        match accum.add(no_vote) {
            // Not enough votes yet.
            Ok(None) => {}
            // Certificate is formed when we have 2f + 1 votes added to accumulator.
            Ok(Some(nc)) => {
                if self.dag.vertex_count(timeout_round) >= self.committee.quorum_size().get() {
                    let nc = nc.clone();
                    actions.extend(self.advance_leader_with_no_vote_certificate(
                        timeout_round,
                        tc,
                        nc,
                    ));
                }
            }
            Err(e) => {
                warn!(t = %timeout_round, %e, "could not add no-vote to vote accumulator");
                if accum.is_empty() {
                    self.rounds.remove(&timeout_round);
                }
            }
        }

        actions
    }

    /// Handle a timeout message of some node.
    ///
    /// Once we have collected more than f timeouts we start broadcasting our own timeout.
    /// Eventually, if we receive more than 2f timeouts we form a timeout certificate and
    /// broadcast that too.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        s = %e.signing_key(),
        t = %e.data().timeout().data().round())
    )]
    pub fn handle_timeout(&mut self, e: Envelope<TimeoutMessage, Validated>) -> Vec<Action> {
        let mut actions = Vec::new();

        let timeout_round = e.data().timeout().data().round();

        if timeout_round < self.round {
            debug!(
                n = %self.public_key(),
                r = %self.round,
                t = %timeout_round,
                "ignoring old timeout"
            );
            return actions;
        }

        let (timeout, evidence) = e.into_data().into_parts();

        let accum = self
            .timeouts
            .entry(timeout_round)
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        let commit = timeout.commitment();
        let votes = accum.votes(&commit);

        if let Err(e) = accum.add(timeout) {
            warn!(t = %timeout_round, %e, "could not add timeout to vote accumulator");
            if accum.is_empty() {
                self.timeouts.remove(&timeout_round);
            }
            return actions;
        }

        // Have we received more than f timeouts?
        if votes != accum.votes(&commit)
            && accum.votes(&commit) == self.committee.threshold().get() + 1
        {
            let t = TimeoutMessage::new(evidence, &self.keypair, self.deterministic);
            let e = Envelope::signed(t, &self.keypair, self.deterministic);
            actions.push(Action::SendTimeout(e))
        }

        // Have we received 2f + 1 timeouts?
        if votes != accum.votes(&commit)
            && accum.votes(&commit) == self.committee.quorum_size().get()
        {
            if let Some(cert) = accum.certificate() {
                actions.push(Action::SendTimeoutCert(cert.clone()))
            } else {
                error!(
                    n = %self.public_key(),
                    r = %self.round,
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
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        t = %cert.data().round())
    )]
    pub fn handle_timeout_cert(&mut self, cert: Certificate<Timeout>) -> Vec<Action> {
        let mut actions = Vec::new();

        let round = cert.data().round();

        if round < self.round() {
            debug!(
                n = %self.public_key(),
                r = %self.round,
                t = %round,
                "ignoring old timeout certificate"
            );
            return actions;
        }

        if !self.has_timeout_cert(cert.data().round()) {
            self.timeouts
                .entry(cert.data().round())
                .or_insert_with(|| VoteAccumulator::new(self.committee.clone()))
                .set_certificate(cert.clone())
        }

        if self.dag.vertex_count(round) >= self.committee.quorum_size().get() {
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
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        x = %round)
    )]
    fn advance_from_round(&mut self, round: RoundNumber, evidence: Evidence) -> Vec<Action> {
        let mut actions = Vec::new();

        // With a leader vertex we can move on to the next round immediately.
        if self.leader_vertex(round).is_some() {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let v = self.create_new_vertex(self.round, evidence);
            actions.extend(self.broadcast_vertex(v.0));
            self.clear_aggregators(self.round);
            self.metrics
                .round_duration
                .add_point(self.metrics_timer.elapsed().as_secs_f64());
            self.metrics_timer = std::time::Instant::now();
            self.metrics.round.set(*self.round as usize);
            return actions;
        }

        // Otherwise check that we have a timeout certificate as evidence:
        let Some(tc) = self
            .timeouts
            .get_mut(&round)
            .and_then(|t| t.certificate())
            .cloned()
        else {
            return actions;
        };

        // We inform the leader of the next round that we did not vote in this round.
        let nvm = NoVoteMessage::new(tc.clone(), &self.keypair, self.deterministic);
        let env = Envelope::signed(nvm, &self.keypair, self.deterministic);
        let leader = self.committee.leader(*round as usize + 1);
        actions.push(Action::SendNoVote(leader, env));

        // If we are not ourselves leader of the next round we can move to it directly.
        if self.public_key() != leader {
            self.round = round + 1;
            actions.push(Action::ResetTimer(self.round));
            let NewVertex(v) = self.create_new_vertex(self.round, tc.into());
            debug_assert!(v.evidence().is_timeout());
            actions.extend(self.broadcast_vertex(v));
            self.clear_aggregators(self.round);
            self.metrics
                .round_duration
                .add_point(self.metrics_timer.elapsed().as_secs_f64());
            self.metrics_timer = std::time::Instant::now();
            self.metrics.round.set(*self.round as usize);
            return actions;
        }

        // As leader of the next round we need to wait for > 2f no-votes of the current round
        // since we have no leader vertex.
        let Some(nc) = self
            .no_votes
            .get(&round)
            .and_then(|n| n.certificate())
            .cloned()
        else {
            return actions;
        };

        actions.extend(self.advance_leader_with_no_vote_certificate(round, tc, nc));
        actions
    }

    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        x = %round)
    )]
    fn advance_leader_with_no_vote_certificate(
        &mut self,
        round: RoundNumber,
        tc: Certificate<Timeout>,
        nc: Certificate<NoVote>,
    ) -> Vec<Action> {
        debug_assert_eq!(tc.data().round(), nc.data().round());
        let mut actions = Vec::new();
        self.round = round + 1;
        actions.push(Action::ResetTimer(self.round));
        let NewVertex(mut v) = self.create_new_vertex(self.round, tc.into());
        v.set_no_vote(nc);
        actions.extend(self.broadcast_vertex(v));
        self.clear_aggregators(self.round);
        self.metrics
            .round_duration
            .add_point(self.metrics_timer.elapsed().as_secs_f64());
        self.metrics_timer = std::time::Instant::now();
        self.metrics.round.set(*self.round as usize);
        actions
    }

    /// Add a new vertex to the DAG and send it as a proposal to nodes.
    #[instrument(level = "trace", skip_all, fields( n = %self.public_key(), r = %self.round, %v))]
    fn broadcast_vertex(&mut self, v: Vertex) -> Vec<Action> {
        let e = Envelope::signed(v, &self.keypair, self.deterministic);
        vec![Action::SendProposal(e)]
    }

    /// Create a new vertex for the given round `r`.
    ///
    /// NB that the returned value requires further processing iff there is no
    /// leader vertex in `r - 1`. In that case a timeout certificate (and potentially
    /// a no-vote certificate) is required.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        v = %r)
    )]
    fn create_new_vertex(&mut self, r: RoundNumber, e: Evidence) -> NewVertex {
        let block = SailfishBlock::empty(r, Timestamp::now(), self.delayed_inbox_index)
            .with_transactions(self.transactions.take());

        let mut new = Vertex::new(r, e, &self.keypair, self.deterministic);

        new.add_edges(self.dag.vertices(r - 1).map(Vertex::source).cloned())
            .set_committed_round(self.committed_round)
            .set_block(block);

        // Every vertex in our DAG has > 2f edges to the previous round:
        debug_assert!(new.num_edges() >= self.committee.quorum_size().get());

        NewVertex(new)
    }

    /// Try to add a vertex to the DAG.
    ///
    /// If all edges of the vertex point to other vertices in the DAG we add the
    /// vertex to the DAG. If we also have more than 2f vertices for the given
    /// round, we can try to commit the leader vertex of a round.
    #[instrument(level = "trace", skip_all, fields(n = %self.public_key(), r = %self.round, %v))]
    fn try_to_add_to_dag(&mut self, v: Vertex) -> Result<Vec<Action>, Vertex> {
        let r = *v.round().data();

        if v.edges().any(|w| self.dag.vertex(r - 1, w).is_none()) {
            if self.round + 2 >= r {
                debug!(
                    n = %self.public_key(),
                    r = %self.round,
                    v = %v,
                    "not all edges are resolved in dag"
                );
                return Err(v);
            }
            if v.edges().any(|w| self.buffer.vertex(r - 1, w).is_none()) {
                warn!(
                    n = %self.public_key(),
                    r = %self.round,
                    v = %v,
                    "not all edges are resolved in buffer"
                );
                return Err(v);
            }
            for w in self.buffer.drain_round(r - 1) {
                self.dag.add(w)
            }
            self.buffer.remove(r);
        }

        let is_genesis_vertex = v.is_genesis();

        self.dag.add(v);
        self.metrics.dag_depth.set(self.dag.depth());

        if is_genesis_vertex {
            // A genesis vertex has no edges to prior rounds.
            return Ok(Vec::new());
        }

        if r <= self.committed_round {
            debug!(
                n = %self.public_key(),
                r = %self.round,
                c = %self.committed_round,
                v = %r,
                "leader has already been committed"
            );
            return Ok(Vec::new());
        }

        if self.dag.vertex_count(r) >= self.committee.quorum_size().get() {
            // We have enough vertices => try to commit the leader vertex:
            let Some(l) = self.leader_vertex(r - 1).cloned() else {
                debug!(
                    n = %self.public_key(),
                    r = %self.round,
                    v = %r,
                    "no leader vertex in vertex round v - 1 => can not commit"
                );
                return Ok(Vec::new());
            };
            // If enough edges to the leader of the previous round exist we can commit the
            // leader vertex.
            if self
                .dag
                .vertices(r)
                .filter(|v| v.has_edge(l.source()))
                .count()
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
    #[instrument(level = "trace", skip_all, fields(n = %self.public_key(), r = %self.round, %v))]
    fn commit_leader(&mut self, mut v: Vertex) -> Vec<Action> {
        debug_assert!(*v.round().data() >= self.committed_round);
        self.leader_stack.push(v.clone());
        for r in (*self.committed_round + 1..**v.round().data()).rev() {
            let Some(l) = self.leader_vertex(r.into()).cloned() else {
                debug! {
                    n = %self.public_key(),
                    r = %self.round,
                    x = %r,
                    "no leader vertex in round x => can not commit"
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
        self.metrics
            .committed_round
            .set(*self.committed_round as usize);
        self.order_vertices()
    }

    /// Order vertices relative to leader vertices.
    ///
    /// Leader vertices are ordered on the leader stack. The other vertices of a round
    /// are ordered arbitrarily, but consistently, relative to the leaders.
    #[instrument(level = "trace", skip_all, fields(n = %self.public_key(), r = %self.round))]
    fn order_vertices(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        while let Some(v) = self.leader_stack.pop() {
            // This orders vertices by round and source.
            for to_deliver in self
                .dag
                .vertex_range(RoundNumber::genesis() + 1..)
                .filter(|w| self.dag.is_connected(&v, w))
            {
                let r = *to_deliver.round().data();
                let s = *to_deliver.source();
                if self.delivered.contains(&(r, s)) {
                    continue;
                }
                let b = to_deliver.block().clone();
                info!(n = %self.public_key(), v = %to_deliver, "deliver");
                actions.push(Action::Deliver(b, r, s));
                self.delivered.insert((r, s));
            }
        }
        self.cleanup();
        actions
    }

    /// Cleanup the DAG and other collections.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        c = %self.committed_round)
    )]
    fn cleanup(&mut self) {
        let r = self
            .committed_round_quorum()
            .saturating_sub(self.committee.size().get() as u64)
            .into();

        if self.committed_round < r {
            return;
        }

        debug!(n = %self.public_key(), %r, "cleaning up to round");

        self.dag.remove(r);
        self.buffer.remove(r);
        self.delivered.retain(|(x, _)| *x >= r);

        // Now add buffered vertices of the lowest round to the DAG. This is assumed to be safe
        // because we are at this point at least `len` rounds ahead of `r` and in each round we
        // have > 2f vertices in our DAG.

        debug_assert!(self.buffer.vertex_count(r) <= self.committee.threshold().get());

        for v in self.buffer.drain_round(r) {
            self.dag.add(v)
        }

        self.metrics.dag_depth.set(self.dag.depth());
        self.metrics.vertex_buffer.set(self.buffer.depth());
        self.metrics.delivered.set(self.delivered.len());
    }

    /// Remove vote aggregators up to the given round.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.public_key(),
        r = %self.round,
        x = %to)
    )]
    fn clear_aggregators(&mut self, to: RoundNumber) {
        if to.is_genesis() {
            return;
        }
        self.rounds = self.rounds.split_off(&(to - 1));
        self.timeouts = self.timeouts.split_off(&(to - 1));
        self.no_votes = self.no_votes.split_off(&(to - 1));
        self.metrics.rounds_buffer.set(self.rounds.len());
        self.metrics.timeout_buffer.set(self.timeouts.len());
        self.metrics.novote_buffer.set(self.no_votes.len())
    }

    /// Validate an incoming vertex.
    ///
    /// Every vertex needs to have more than 2f edges. In addition, a
    /// vertex needs to have either a path to the leader vertex of the
    /// previous round, or a timeout certificate and (if from the leader) a
    /// no-vote certificate.
    #[instrument(level = "trace", skip_all, fields(n = %self.public_key(), r = %self.round, %v))]
    fn is_valid(&self, v: &Vertex) -> bool {
        if v.is_genesis() {
            info!(n = %self.public_key(), r = %self.round, %v, "accepting genesis vertex");
            return true;
        }

        if *v.round().data() < self.dag.min_round().unwrap_or_else(RoundNumber::genesis) {
            debug!(n = %self.public_key(), r = %self.round, %v, "vertex round is too old");
            return false;
        }

        if *v.round().data() < v.committed_round() {
            warn!(
                n = %self.public_key(),
                r = %self.round,
                %v,
                "vertex round is less than committed round"
            );
            return false;
        }

        if v.has_edge(&self.committee.leader(**v.round().data() as usize - 1)) {
            return true;
        }

        if v.source() != &self.committee.leader(**v.round().data() as usize) {
            return true;
        }

        if v.no_vote_cert().is_none() {
            warn!(
                n = %self.public_key(),
                r = %self.round,
                v = %v,
                "vertex is missing no-vote certificate"
            );
            return false;
        };

        true
    }

    fn leader_vertex(&self, r: RoundNumber) -> Option<&Vertex> {
        self.dag.vertex(r, &self.committee.leader(*r as usize))
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

    fn has_timeout_cert(&self, r: RoundNumber) -> bool {
        self.timeouts
            .get(&r)
            .map(|a| a.certificate().is_some())
            .unwrap_or(false)
    }

    fn committed_round_quorum(&self) -> RoundNumber {
        let mut rounds = self
            .peers
            .values()
            .map(|info| info.committed_round)
            .collect::<Vec<_>>();

        rounds.sort_unstable_by(|x, y| y.cmp(x));

        rounds
            .get(self.committee.quorum_size().get() - 1)
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(feature = "test")]
impl Consensus {
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    pub fn buffer_depth(&self) -> usize {
        self.buffer.depth()
    }

    pub fn delivered(&self) -> &HashSet<(RoundNumber, PublicKey)> {
        &self.delivered
    }

    pub fn leader_stack(&self) -> &Vec<Vertex> {
        &self.leader_stack
    }

    pub fn committed_round(&self) -> RoundNumber {
        self.committed_round
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    pub fn no_vote_accumulators(&self) -> &BTreeMap<RoundNumber, VoteAccumulator<NoVote>> {
        &self.no_votes
    }

    pub fn timeout_accumulators(&self) -> &BTreeMap<RoundNumber, VoteAccumulator<Timeout>> {
        &self.timeouts
    }

    pub fn sign<D>(&self, d: D) -> Envelope<D, Validated>
    where
        D: committable::Committable,
    {
        Envelope::signed(d, &self.keypair, self.deterministic)
    }
}
