mod dag;
mod metrics;

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::time::Instant;

use committable::Committable;
use multisig::{Certificate, Committee, Envelope, Keypair, PublicKey, Validated, VoteAccumulator};
use multisig::{CommitteeId, KeyId};
use sailfish_types::{
    Action, Evidence, GENESIS_ROUND, Message, NoVote, NoVoteMessage, Timeout, TimeoutMessage,
};
use sailfish_types::{ConsensusTime, Handover, HandoverMessage, NodeInfo};
use sailfish_types::{DataSource, HasTime, Payload, Round, RoundNumber, Vertex};
use sailfish_types::{Info, math};
use tracing::{Level, debug, enabled, error, info, trace, warn};

pub use dag::Dag;
pub use metrics::ConsensusMetrics;

#[cfg(feature = "times")]
use sailfish_types::time_series::{DELIVERED, ROUND_START};

/// A `NewVertex` may need to have a timeout or no-vote certificate set.
struct NewVertex<T>(Vertex<T>);

/// Information about the next committee.
struct NextCommittee {
    id: CommitteeId,
    start: ConsensusTime,
}

/// Consensus instance state.
///
/// State transitions are directed and acyclic, e.g. an instance
/// that shut down will not go back to `Startup` or `Running`.
#[derive(Clone, Copy)]
enum State {
    /// Initial state.
    Startup,
    /// Normal operating state.
    ///
    /// Entered either via `Consensus::go` or after handover from
    /// the previous committee is complete.
    Running,
    /// Instance is terminating.
    ///
    /// Entered when starting the handover to the next committee.
    Shutdown(RoundNumber),
}

impl State {
    fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }

    fn is_shutdown(self) -> bool {
        matches!(self, Self::Shutdown(_))
    }
}

pub struct Consensus<T> {
    /// The key index of the node.
    key_id: KeyId,

    /// The public and private key of this node.
    keypair: Keypair,

    /// Clock driven by median of timestamps in a round.
    clock: ConsensusTime,

    /// The DAG of vertices.
    dag: Dag<T>,

    /// Operating state.
    state: State,

    /// The quorum membership.
    committee: Committee,

    /// Information about the next committee.
    next_committee: Option<NextCommittee>,

    /// Handover votes from the previous committee.
    handovers: Option<VoteAccumulator<Handover>>,

    /// The current round number.
    round: RoundNumber,

    /// The last committed round number.
    committed_round: RoundNumber,

    /// Information about committee members.
    nodes: NodeInfo<KeyId, RoundNumber>,

    /// The set of vertices that we've received so far.
    buffer: Dag<T>,

    /// The set of values we have delivered so far.
    delivered: HashSet<(RoundNumber, KeyId)>,

    /// The set of round number confirmations that we've received so far per round.
    rounds: BTreeMap<RoundNumber, VoteAccumulator<Round>>,

    /// The set of timeouts that we've received so far per round.
    timeouts: BTreeMap<RoundNumber, VoteAccumulator<Timeout>>,

    /// The set of no votes that we've received so far.
    no_votes: BTreeMap<RoundNumber, VoteAccumulator<NoVote>>,

    /// Stack of leader vertices.
    leader_stack: Vec<Vertex<T>>,

    /// Source of payload data to include in vertex proposals.
    datasource: Box<dyn DataSource<Data = T> + Send>,

    /// The consensus metrics for this node.
    metrics: ConsensusMetrics,

    /// The timer for recording metrics related to duration of consensus operations.
    metrics_timer: std::time::Instant,
}

impl<T> Consensus<T> {
    pub fn with_metrics(mut self, m: ConsensusMetrics) -> Self {
        self.metrics = m;
        self
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn committed_round(&self) -> RoundNumber {
        self.committed_round
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    pub fn set_next_committee(&mut self, start: ConsensusTime, c: CommitteeId) {
        self.next_committee = Some(NextCommittee { start, id: c })
    }

    pub fn set_handover_committee(&mut self, c: Committee) {
        self.handovers = Some(VoteAccumulator::new(c))
    }
}

impl<T> Consensus<T>
where
    T: Committable + HasTime + Clone + PartialEq,
{
    pub fn new<D>(keypair: Keypair, committee: Committee, datasource: D) -> Self
    where
        D: DataSource<Data = T> + Send + 'static,
    {
        let key_id = committee
            .get_index(&keypair.public_key())
            .expect("keypair in committee");
        Self {
            key_id,
            keypair,
            state: State::Startup,
            clock: ConsensusTime(Default::default()),
            nodes: NodeInfo::new(committee.quorum_size()),
            dag: Dag::new(committee.size()),
            round: GENESIS_ROUND,
            committed_round: GENESIS_ROUND,
            buffer: Dag::new(committee.size()),
            delivered: HashSet::new(),
            rounds: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            no_votes: BTreeMap::new(),
            handovers: None,
            committee,
            next_committee: None,
            leader_stack: Vec::new(),
            datasource: Box::new(datasource),
            metrics: Default::default(),
            metrics_timer: Instant::now(),
        }
    }

    /// (Re-)start consensus.
    ///
    /// This continues with the highest round number found in the DAG (or else
    /// starts from the genesis round).
    pub fn go(&mut self, d: Dag<T>, e: Evidence) -> Vec<Action<T>> {
        info!(node = %self.public_key(), round = %self.round(), "start consensus");

        let r = d.max_round().unwrap_or(GENESIS_ROUND);

        self.dag = d;
        self.round = r;

        assert!(matches!(self.state, State::Startup));
        self.state = State::Running;

        let actions = if r.is_genesis() {
            let vtx = Vertex::new(
                Round::new(r, self.committee.id()),
                Evidence::Genesis,
                self.datasource.next(r),
                self.key_id,
                &self.keypair,
            );
            let env = Envelope::signed(vtx, &self.keypair);
            let rnd = Round::new(r, self.committee.id());
            #[cfg(feature = "times")]
            times::record(ROUND_START, *env.data().round().data().num());
            vec![Action::SendProposal(env), Action::ResetTimer(rnd)]
        } else {
            self.advance_from_round(r, e)
        };

        trace!(
            target: "sf-trace",
            node    = %self.public_key(),
            round   = %self.round,
            rleader = %self.committee.leader(*self.round as usize),
            trace   = ?actions.iter().map(|a| Trace::Action(a).to_string()).collect::<Vec<_>>()
        );

        actions
    }

    /// Main entry point to process a `Message`.
    pub fn handle_message(&mut self, m: Message<T, Validated>) -> Vec<Action<T>> {
        debug!(
            node      = %self.public_key(),
            round     = %self.round,
            msg       = %m,
            committed = %self.committed_round,
            buffer    = %self.buffer.depth(),
            delivered = %self.delivered.len(),
            leaders   = %self.leader_stack.len(),
            timeouts  = %self.timeouts.len(),
            dag       = %self.dag.depth(),
            "handle message"
        );

        let round = m.round().num();

        trace!(
            target: "sf-trace",
            node    = %self.public_key(),
            round   = %self.round,
            mleader = %self.committee.leader(*round as usize),
            trace  = ?[Trace::Message(&m).to_string()],
            dag    = ?self.dag.vertices(round).map(|v| v.to_string()).collect::<Vec<_>>()
        );

        if let State::Shutdown(r) = self.state {
            if round > r {
                debug!(
                    node     = %self.public_key(),
                    shutdown = %r,
                    msg      = %m,
                    "consensus instance shut down"
                );
                return Vec::new();
            }
        }

        let actions = match m {
            Message::Vertex(e) => {
                trace!(
                    target: "sf-trace",
                    node    = %self.public_key(),
                    round   = %self.round,
                    mleader = %self.committee.leader(*round as usize),
                    vertex  = %e.data(),
                    edges   = ?e.data().edges().collect::<Vec<_>>(),
                );
                self.handle_vertex(e)
            }
            Message::NoVote(e) => self.handle_no_vote(e),
            Message::Timeout(e) => self.handle_timeout(e),
            Message::Handover(e) => self.handle_handover(e),
            Message::TimeoutCert(c) => self.handle_timeout_cert(c),
            Message::HandoverCert(c) => self.handle_handover_cert(c),
        };

        trace!(
            target: "sf-trace",
            node    = %self.public_key(),
            round   = %self.round,
            rleader = %self.committee.leader(*self.round as usize),
            trace   = ?actions.iter().map(|a| Trace::Action(a).to_string()).collect::<Vec<_>>()
        );

        actions
    }

    /// Handle information events.
    pub fn handle_info(&mut self, i: Info) -> Vec<Action<T>> {
        trace!(
            target: "sf-trace",
            node  = %self.public_key(),
            round = %self.round,
            trace = ?[Trace::<T>::Info(&i).to_string()]
        );
        match i {
            Info::LeaderThresholdReached(r) => {
                if r <= self.committed_round {
                    return Vec::new();
                }
                let Some(l) = self.leader_vertex(r).cloned() else {
                    return Vec::new();
                };
                debug!(
                    node  = %self.public_key(),
                    round = %r,
                    "commit leader upon 2t+1 first messages of next round"
                );
                self.commit_leader(l)
            }
        }
    }

    /// An internal timeout occurred.
    ///
    /// This means we did not receive a leader vertex in a round and
    /// results in a timeout message being broadcasted to all nodes.
    pub fn timeout(&mut self, r: Round) -> Vec<Action<T>> {
        info!(node = %self.public_key(), round = %r, "internal timeout");
        trace!(
            target: "sf-trace",
            node    = %self.public_key(),
            round   = %self.round,
            tleader = %self.committee.leader(*r.num() as usize),
            trace   = ?[Trace::<T>::Timeout(r).to_string()]
        );
        debug_assert_eq!(r.num(), self.round());
        let e = if r.num().is_genesis() {
            Evidence::Genesis
        } else {
            self.evidence(r.num() - 1)
                .expect("evidence for previous round exists")
        };
        let t = TimeoutMessage::new(self.committee.id(), e, &self.keypair);
        let e = Envelope::signed(t, &self.keypair);
        self.metrics.rounds_timed_out.add(1);
        vec![Action::SendTimeout(e)]
    }

    /// Handle a vertex proposal of some node.
    ///
    /// We validate the vertex and try to add it to our DAG. If the vertex is valid
    /// but we can not yet add it (e.g. because not all of its edges resolve to other
    /// DAG elements yet), we store it in a buffer and retry adding it once we have
    /// received another vertex which we sucessfully added.
    pub fn handle_vertex(&mut self, e: Envelope<Vertex<T>, Validated>) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), vertex = %e.data(), "handle vertex message");

        let mut actions = Vec::new();

        let v = e.into_data();

        if self.dag.contains(&v) || self.buffer.contains(&v) {
            debug!(node = %self.public_key(), vertex = %v, "duplicate vertex");
            return actions;
        }

        if !self.is_valid(&v) {
            return actions;
        }

        self.nodes.record(v.source(), v.committed_round());

        if self.is_restart_required() {
            actions.push(Action::RestartRequired)
        }

        if v.round().data().num() < self.dag.min_round().unwrap_or(GENESIS_ROUND) {
            debug!(
                node   = %self.public_key(),
                round  = %self.round,
                vertex = %v,
                "vertex round is too old"
            );
            return actions;
        }

        if v.round().data().num() < v.committed_round() {
            warn!(node = %self.public_key(), vertex = %v, "vertex round < committed round");
            return actions;
        }

        let accum = self
            .rounds
            .entry(v.round().data().num())
            .or_insert_with(|| VoteAccumulator::new(self.committee.clone()));

        if let Err(e) = accum.add(v.round().clone()) {
            warn!(
                node   = %self.keypair.public_key(),
                vertex = %v,
                err    = %e,
                "failed to add round to evidence"
            );
            if accum.is_empty() {
                self.rounds.remove(&v.round().data().num());
            }
            return actions;
        }

        if self.committed_round < self.lower_round_bound() {
            actions.extend(self.cleanup());
            actions.extend(self.try_to_add_to_dag_from_buffer());
        }

        let quorum = self.committee.quorum_size().get();

        let r = v.round().data().num();
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
                            node  = %self.public_key(),
                            round = %r,
                            "no evidence for vertex round exists outside of dag"
                        );
                    }
                }
                actions.extend(self.try_to_add_to_dag_from_buffer());
            }
        }

        actions
    }

    /// Handle a no-vote message received.
    ///
    /// Upon receiving a no vote message we:
    /// - Verify that we are the leader for round `r + 1` from timeout round `r`.
    /// - Check if we have a timeout certificate for the round, or else set it.
    /// - Add the `no_vote` to our `VoteAccumulator`. Upon receiving `2f + 1` `no_votes` a
    ///   certificate will be created.
    /// - If a no-vote certificate has been created, advance to the next round with the `no_vote`
    ///   and `timeout_certificate`.
    pub fn handle_no_vote(&mut self, e: Envelope<NoVoteMessage, Validated>) -> Vec<Action<T>> {
        trace!(
            node    = %self.public_key(),
            signer  = %e.signing_key(),
            no_vote = %e.data().no_vote().data().round(),
            "no-vote message"
        );

        let mut actions = Vec::new();

        let timeout_round = e.data().no_vote().data().round().num();

        if timeout_round < self.round {
            debug!(node = %self.public_key(), no_vote = %timeout_round, "ignoring old no-vote");
            return actions;
        }

        // Here the no-vote is sent from round r - 1 to leader in round r that is why we add 1 to
        // round to get correct leader
        if self.public_key() != self.committee.leader(*timeout_round as usize + 1) {
            warn!(
                node    = %self.public_key(),
                no_vote = %timeout_round,
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
                warn!(
                    node    = %self.keypair.public_key(),
                    no_vote = %timeout_round,
                    err     = %e,
                    "could not add no-vote to vote accumulator"
                );
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
    pub fn handle_timeout(&mut self, e: Envelope<TimeoutMessage, Validated>) -> Vec<Action<T>> {
        trace!(
            node    = %self.public_key(),
            signer  = %e.signing_key(),
            timeout = %e.data().timeout().data().round(),
            "timeout message"
        );

        let mut actions = Vec::new();

        let timeout_round = e.data().timeout().data().round().num();

        if timeout_round < self.round {
            debug!(node = %self.public_key(), timout = %timeout_round, "ignoring old timeout");
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
            warn!(
                node    = %self.keypair.public_key(),
                timeout = %timeout_round,
                err     = %e,
                "could not add timeout to vote accumulator"
            );
            if accum.is_empty() {
                self.timeouts.remove(&timeout_round);
            }
            return actions;
        }

        // Have we received more than f timeouts?
        if votes != accum.votes(&commit)
            && accum.votes(&commit) == self.committee.one_honest_threshold().get()
        {
            let t = TimeoutMessage::new(self.committee.id(), evidence, &self.keypair);
            let e = Envelope::signed(t, &self.keypair);
            actions.push(Action::SendTimeout(e))
        }

        // Have we received 2f + 1 timeouts?
        if votes != accum.votes(&commit)
            && accum.votes(&commit) == self.committee.quorum_size().get()
        {
            if let Some(cert) = accum.certificate() {
                actions.push(Action::SendTimeoutCert(cert.clone()))
            } else {
                error!(node = %self.public_key(), "no timeout certificate despite enough votes");
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
    pub fn handle_timeout_cert(&mut self, cert: Certificate<Timeout>) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), timeout = %cert.data().round(), "timeout certificate");

        let mut actions = Vec::new();

        let round = cert.data().round().num();

        if round < self.round {
            debug!(node = %self.public_key(), timout = %round, "ignoring old timeout certificate");
            return actions;
        }

        if !self.has_timeout_cert(round) {
            self.timeouts
                .entry(round)
                .or_insert_with(|| VoteAccumulator::new(self.committee.clone()))
                .set_certificate(cert.clone())
        }

        if self.dag.vertex_count(round) >= self.committee.quorum_size().get() {
            actions.extend(self.advance_from_round(round, cert.into()));
        }

        actions
    }

    /// Members of the next committee receive handover messages.
    pub fn handle_handover(&mut self, e: Envelope<HandoverMessage, Validated>) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), round = %e.data().handover().data().round(), "handover");

        let mut actions = Vec::new();

        let (handover, _) = e.into_signed().into_data().into_parts();

        let Some(handovers) = &mut self.handovers else {
            warn!(
                node     = %self.keypair.public_key(),
                handover = %handover.data(),
                "unexpected handover message"
            );
            return actions;
        };

        match handovers.add(handover) {
            Ok(Some(cert)) => {
                let cert = cert.clone();
                actions.push(Action::SendHandoverCert(cert.clone()));
                actions.extend(self.start_committee(cert))
            }
            Ok(None) => {}
            Err(err) => {
                warn!(
                    node = %self.keypair.public_key(),
                    err  = %err,
                    "could not add handover data to vote accumulator"
                )
            }
        }

        actions
    }

    /// Members of the next committee receive handover certificates.
    pub fn handle_handover_cert(&mut self, cert: Certificate<Handover>) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), round = %cert.data().round(), "handover certificate");
        let Some(handovers) = &mut self.handovers else {
            warn!(
                node     = %self.keypair.public_key(),
                handover = %cert.data(),
                "unexpected handover certificate"
            );
            return Vec::new();
        };
        handovers.set_certificate(cert.clone());
        self.start_committee(cert)
    }

    /// Try to advance from the given round `r` to `r + 1`.
    ///
    /// We can only advance to the next round if
    ///
    ///   1. we have a leader vertex in `r`, or else
    ///   2. we have a timeout certificate for `r`, and,
    ///   3. if we are leader of `r + 1`, we have a no-vote certificate for `r`.
    fn advance_from_round(&mut self, round: RoundNumber, evidence: Evidence) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), from = %round, "advance round");

        let mut actions = Vec::new();

        // With a leader vertex we can move on to the next round immediately.
        if self.leader_vertex(round).is_some() {
            self.round = round + 1;
            actions.push(Action::ResetTimer(Round::new(
                self.round,
                self.committee.id(),
            )));
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
        let nvm = NoVoteMessage::new(tc.clone(), &self.keypair);
        let env = Envelope::signed(nvm, &self.keypair);
        let leader = self.committee.leader(*round as usize + 1);
        actions.push(Action::SendNoVote(leader, env));

        // If we are not ourselves leader of the next round we can move to it directly.
        if self.public_key() != leader {
            self.round = round + 1;
            actions.push(Action::ResetTimer(Round::new(
                self.round,
                self.committee.id(),
            )));
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

    /// Advances the leader from timeout round `r`.
    ///
    /// This function advances the leader of `r + 1`. The required timeout and
    /// no-vote certificates will be attached to the newly created vertex this
    /// node will broadcast.
    fn advance_leader_with_no_vote_certificate(
        &mut self,
        round: RoundNumber,
        tc: Certificate<Timeout>,
        nc: Certificate<NoVote>,
    ) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), from = %round, "advance with no-vote certificate");
        debug_assert_eq!(tc.data().round(), nc.data().round());
        let mut actions = Vec::new();
        self.round = round + 1;
        actions.push(Action::ResetTimer(Round::new(
            self.round,
            self.committee.id(),
        )));
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
    fn broadcast_vertex(&mut self, v: Vertex<T>) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), vertex = %v, "broadcast vertex");
        let e = Envelope::signed(v, &self.keypair);
        #[cfg(feature = "times")]
        times::record(ROUND_START, *e.data().round().data().num());
        vec![Action::SendProposal(e)]
    }

    /// Create a new vertex for the given round `r`.
    ///
    /// NB that the returned value requires further processing iff there is no
    /// leader vertex in `r - 1`. In that case a timeout certificate (and potentially
    /// a no-vote certificate) is required.
    fn create_new_vertex(&mut self, r: RoundNumber, e: Evidence) -> NewVertex<T> {
        trace!(node = %self.public_key(), next = %r, "create new vertex");

        let payload = self.datasource.next(r);
        let mut new = Vertex::new(
            Round::new(r, self.committee.id()),
            e,
            payload,
            self.key_id,
            &self.keypair,
        );
        new.add_edges(self.dag.vertices(r - 1).map(Vertex::source))
            .set_committed_round(self.committed_round);

        // Every vertex in our DAG has > 2f edges to the previous round:
        debug_assert!(new.num_edges() >= self.committee.quorum_size().get());

        NewVertex(new)
    }

    /// Try to add a vertex to the DAG.
    ///
    /// If all edges of the vertex point to other vertices in the DAG we add the
    /// vertex to the DAG. If we also have more than 2f vertices for the given
    /// round, we can try to commit the leader vertex of a round.
    #[allow(clippy::result_large_err)]
    fn try_to_add_to_dag(&mut self, v: Vertex<T>) -> Result<Vec<Action<T>>, Vertex<T>> {
        trace!(node = %self.public_key(), vertex = %v, "try to add to dag");

        let r = v.round().data().num();

        if v.edges().any(|w| self.dag.vertex(r - 1, w).is_none()) {
            if enabled!(Level::DEBUG) {
                let missing = v.edges().filter(|w| self.dag.vertex(r - 1, *w).is_none());
                debug!(
                    node    = %self.public_key(),
                    vertex  = %v,
                    missing = ?missing.take(3).collect::<Vec<_>>(),
                    "not all edges are resolved in dag"
                );
            }
            return Err(v);
        }

        let is_genesis_vertex = v.is_genesis() || v.is_first_after_handover();

        self.dag.add(v);
        self.metrics.dag_depth.set(self.dag.depth());

        if is_genesis_vertex {
            // A genesis vertex has no edges to prior rounds.
            return Ok(Vec::new());
        }

        if r <= self.committed_round {
            debug!(
                node      = %self.public_key(),
                committed = %self.committed_round,
                round     = %r,
                "leader has already been committed"
            );
            return Ok(Vec::new());
        }

        if self.dag.vertex_count(r) >= self.committee.quorum_size().get() {
            // We have enough vertices => try to commit the leader vertex:
            let Some(l) = self.leader_vertex(r - 1).cloned() else {
                debug!(
                    node  = %self.public_key(),
                    round = %r,
                    "no leader vertex in vertex round - 1 => can not commit"
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

    /// Go over buffered vertices in increasing round number and try to add
    /// each vertex to the DAG as per the usual constraints.
    fn try_to_add_to_dag_from_buffer(&mut self) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), "try to add to dag from buffer");

        let mut actions = Vec::new();

        let quorum = self.committee.quorum_size().get();

        for (.., v) in self.buffer.drain() {
            let r = v.round().data().num();
            match self.try_to_add_to_dag(v) {
                Ok(a) => {
                    actions.extend(a);
                    if r >= self.round && self.dag.vertex_count(r) >= quorum {
                        if let Some(e) = self.evidence(r) {
                            actions.extend(self.advance_from_round(r, e))
                        } else {
                            warn!(
                                node  = %self.public_key(),
                                round = %r,
                                "no evidence for vertex round exists outside of dag"
                            );
                        }
                    }
                }
                Err(v) => {
                    self.buffer.add(v);
                }
            }
        }

        self.metrics.vertex_buffer.set(self.buffer.depth());
        actions
    }

    /// Commit a leader vertex.
    ///
    /// Leader vertices are organised in a stack, with other vertices of a round
    /// ordered relative to them (cf. `order_vertices`).
    ///
    /// In addition to committing the argument vertex, this will also commit leader
    /// vertices between the last previously committed leader vertex and the current
    /// leader vertex, if there is a path between them.
    fn commit_leader(&mut self, mut v: Vertex<T>) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), vertex = %v, "commit leader");
        debug_assert!(v.round().data().num() >= self.committed_round);
        self.leader_stack.push(v.clone());
        for r in (*self.committed_round + 1..*v.round().data().num()).rev() {
            let Some(l) = self.leader_vertex(r.into()).cloned() else {
                debug!(
                    node  = %self.public_key(),
                    round = %r,
                    "no leader vertex in round => can not commit"
                );
                continue;
            };
            if self.dag.is_connected(&v, &l) {
                self.leader_stack.push(l.clone());
                v = l
            }
        }
        self.committed_round = v.round().data().num();
        trace!(node = %self.public_key(), commit = %self.committed_round, "committed round");
        self.metrics
            .committed_round
            .set(*self.committed_round as usize);
        self.order_vertices()
    }

    /// Order vertices relative to leader vertices.
    ///
    /// Leader vertices are ordered on the leader stack. The other vertices of a round
    /// are ordered arbitrarily, but consistently, relative to the leaders.
    fn order_vertices(&mut self) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), "order vertices");
        let mut actions = Vec::new();
        while let Some(v) = self.leader_stack.pop() {
            // This orders vertices by round and source.
            for to_deliver in self
                .dag
                .vertex_range(GENESIS_ROUND + 1..)
                .filter(|w| self.dag.is_connected(&v, w))
            {
                let r = to_deliver.round().data();
                let s = to_deliver.source();
                if self.delivered.contains(&(r.num(), s)) {
                    continue;
                }
                let b = to_deliver.payload().clone();
                let e = to_deliver.evidence().clone();
                info!(node = %self.public_key(), vertex = %to_deliver, "deliver");
                #[cfg(feature = "times")]
                times::record_once(DELIVERED, *r.num());
                actions.push(Action::Deliver(Payload::new(*r, s, b, e)));
                self.delivered.insert((r.num(), s));
            }
        }
        // If there is an upcoming committee change, start the clock and
        // eventually send a handover message to the next committee.
        if self.next_committee.is_some() {
            tick(&actions, &mut self.clock);
            if let Some(handover) = self.handover() {
                let e = self
                    .evidence(handover.round().num())
                    .expect("evidence for committed round");
                let m = HandoverMessage::new(handover, e, &self.keypair);
                let e = Envelope::signed(m, &self.keypair);
                actions.push(Action::SendHandover(e))
            }
        }
        actions.extend(self.cleanup());
        actions
    }

    /// Cleanup the DAG and other collections.
    fn cleanup(&mut self) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), "cleanup");
        let mut actions = Vec::new();

        let r = self.lower_round_bound();

        debug!(
            node      = %self.public_key(),
            round     = %self.round,
            committed = %self.committed_round,
            cutoff    = %r,
            "cleaning up to round"
        );

        self.dag.remove(r);
        self.buffer.remove(r);
        self.delivered.retain(|(x, _)| *x >= r);

        if self.dag.is_empty() {
            if let Some(r) = self.first_available_round() {
                debug!(
                    node  = %self.public_key(),
                    round = %r,
                    "moving buffered round into empty dag"
                );
                self.buffer.remove(r);
                for v in self.buffer.drain_round(r) {
                    self.dag.add(v)
                }
                actions.push(Action::Catchup(Round::new(r, self.committee.id())));
            }
        } else if self.committed_round >= self.nodes.quorum().copied().unwrap_or(GENESIS_ROUND) {
            for v in self.buffer.drain_round(r) {
                self.dag.add(v)
            }
        }

        self.metrics.dag_depth.set(self.dag.depth());
        self.metrics.vertex_buffer.set(self.buffer.depth());
        self.metrics.delivered.set(self.delivered.len());

        actions.push(Action::Gc(Round::new(r, self.committee.id())));
        actions
    }

    /// Remove vote aggregators up to the given round.
    fn clear_aggregators(&mut self, to: RoundNumber) {
        trace!(node = %self.public_key(), to = %to, "clear aggregators");
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
    fn is_valid(&self, v: &Vertex<T>) -> bool {
        trace!(node = %self.public_key(), vertex = %v, "check vertex");

        if v.is_genesis() {
            info!(
                node   = %self.public_key(),
                round  = %self.round,
                vertex = %v,
                "accepting genesis vertex"
            );
            return true;
        }

        if v.is_first_after_handover() {
            info!(
                node   = %self.public_key(),
                round  = %self.round,
                vertex = %v,
                "accepting first vertex after handover"
            );
            return true;
        }

        let prev_leader = self
            .committee
            .leader_index(*v.round().data().num() as usize - 1);

        if v.has_edge(prev_leader) {
            return true;
        }

        let leader = self
            .committee
            .leader_index(*v.round().data().num() as usize);

        if v.source() != leader {
            return true;
        }

        if v.no_vote_cert().is_none() {
            warn!(
                node   = %self.public_key(),
                vertex = %v,
                "vertex is missing no-vote certificate"
            );
            return false;
        };

        true
    }

    /// Retrieve leader vertex for a given round.
    fn leader_vertex(&self, r: RoundNumber) -> Option<&Vertex<T>> {
        self.dag.vertex(r, self.committee.leader_index(*r as usize))
    }

    /// Do we have `Evidence` that a message is valid for a given round?
    fn evidence(&self, r: RoundNumber) -> Option<Evidence> {
        if let Some(cert) = self.rounds.get(&r).and_then(|a| a.certificate()) {
            return Some(Evidence::Regular(cert.clone()));
        }
        if let Some(cert) = self.timeouts.get(&r).and_then(|a| a.certificate()) {
            return Some(Evidence::Timeout(cert.clone()));
        }
        if let Some(cert) = self.handovers.as_ref().and_then(|a| a.certificate()) {
            if cert.data().round().num() == r {
                return Some(Evidence::Handover(cert.clone()));
            }
        }
        None
    }

    /// Do we have a given timeout certificate for a given round?
    fn has_timeout_cert(&self, r: RoundNumber) -> bool {
        self.timeouts
            .get(&r)
            .map(|a| a.certificate().is_some())
            .unwrap_or(false)
    }

    /// Find the first round in our buffer that we have a quorum of vertices for.
    fn first_available_round(&self) -> Option<RoundNumber> {
        self.buffer
            .rounds()
            .find(|r| self.buffer.vertex_count(*r) >= self.committee.quorum_size().get())
    }

    /// Cutoff round for cleanup and catch-up logic.
    ///
    /// It is defined as the quorum of committed round numbers of the committee
    /// minus an extra margin to avoid overly aggressive cleanup.
    fn lower_round_bound(&self) -> RoundNumber {
        self.nodes
            .quorum()
            .copied()
            .unwrap_or(GENESIS_ROUND)
            .saturating_sub(self.committee.quorum_size().get() as u64)
            .into()
    }

    /// Is this node part of a minority that did not restart?
    ///
    /// If we detect that a quorum of committee members is submitting vertex
    /// proposals for rounds less than our committed round minus some margin
    /// we assume that the quorum has restarted and we are in a minority that
    /// did not. Then we should also restart to rejoin the others.
    fn is_restart_required(&self) -> bool {
        let max = self
            .nodes
            .quorum_rev()
            .copied()
            .map(u64::from)
            .unwrap_or(u64::MAX);
        let min = self
            .committed_round
            .saturating_sub(self.committee.size().get() as u64);
        if max < min {
            error!(node = %self.public_key(), %min, %max, "restart required");
            true
        } else {
            false
        }
    }

    /// Called by the current committee to see if the handover should be started.
    fn handover(&mut self) -> Option<Handover> {
        let next = self.next_committee.as_mut()?;
        if self.state.is_shutdown() || next.start > self.clock {
            return None;
        }
        info!(node = %self.keypair.public_key(), round = %self.committed_round, "starting handover");
        let r = Round::new(self.committed_round, self.committee.id());
        self.state = State::Shutdown(self.committed_round);
        Some(Handover::new(r, next.id))
    }

    /// A new committee starts here, once the handover is complete.
    fn start_committee(&mut self, cert: Certificate<Handover>) -> Vec<Action<T>> {
        trace!(node = %self.public_key(), handover = %cert.data(), "start committee");

        let mut actions = Vec::new();

        let r = cert.data().round().num();

        if self.state.is_running() {
            return actions;
        }

        self.state = State::Running;
        self.committed_round = r;
        self.round = r + 1;

        let round = Round::new(self.round, self.committee.id());

        let mut vertex = Vertex::new(
            round,
            Evidence::Handover(cert),
            self.datasource.next(self.round),
            self.key_id,
            &self.keypair,
        );
        vertex.set_committed_round(r);
        let env = Envelope::signed(vertex, &self.keypair);

        #[cfg(feature = "times")]
        times::record(ROUND_START, *env.data().round().data().num());

        actions.extend([
            Action::UseCommittee(round),
            Action::SendProposal(env),
            Action::ResetTimer(Round::new(self.round, self.committee.id())),
        ]);

        actions
    }
}

/// Trace log helper.
#[derive(Debug)]
enum Trace<'a, T: Committable> {
    Timeout(Round),
    Action(&'a Action<T>),
    Message(&'a Message<T, Validated>),
    Info(&'a Info),
}

impl<T: Committable> fmt::Display for Trace<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Timeout(r) => write!(f, "T({r})"),
            Self::Action(a) => write!(f, "A({a})"),
            Self::Message(m) => write!(f, "M({m})"),
            Self::Info(i) => write!(f, "I({i})"),
        }
    }
}

#[cfg(feature = "test")]
impl<T: Committable + Eq> Consensus<T> {
    pub fn dag(&self) -> &Dag<T> {
        &self.dag
    }

    pub fn buffer_depth(&self) -> usize {
        self.buffer.depth()
    }

    pub fn delivered(&self) -> impl Iterator<Item = (RoundNumber, KeyId)> + '_ {
        self.delivered.iter().copied()
    }

    pub fn leader_stack(&self) -> &[Vertex<T>] {
        &self.leader_stack
    }

    pub fn no_vote_accumulators(
        &self,
    ) -> impl Iterator<Item = (RoundNumber, &VoteAccumulator<NoVote>)> {
        self.no_votes.iter().map(|(r, v)| (*r, v))
    }

    pub fn timeout_accumulators(
        &self,
    ) -> impl Iterator<Item = (RoundNumber, &VoteAccumulator<Timeout>)> {
        self.timeouts.iter().map(|(r, v)| (*r, v))
    }
}

fn tick<T>(actions: &[Action<T>], ct: &mut ConsensusTime)
where
    T: Committable + HasTime,
{
    let mut actions = actions.iter().peekable();
    let mut frontier = Vec::new();

    // Go over all actions and calculate the median timestamp for
    // each sequence of consecutive deliver actions by collecting
    // the individual timestamp of each payload.
    while actions.peek().is_some() {
        let times = (&mut actions)
            .skip_while(|a| !a.is_deliver())
            .map_while(|a| {
                if let Action::Deliver(p) = a {
                    Some(u64::from(p.data().time()))
                } else {
                    None
                }
            });

        frontier.clear();
        frontier.extend(times);

        if let Some(t) = math::median(&mut frontier) {
            *ct = ConsensusTime(t.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use arbtest::{arbitrary::Arbitrary, arbtest};
    use multisig::KeyId;
    use sailfish_types::{Evidence, Round, Timestamp, math};

    use super::{Action, ConsensusTime, Payload, tick};

    #[test]
    fn consensus_time() {
        const N: usize = 19; // number of timestamps
        arbtest(|u| {
            // Some fake values of no concern to this test:
            let r = Round::new(u64::arbitrary(u)?, u64::arbitrary(u)?);
            let k = KeyId::from(u8::arbitrary(u)?);
            let e = Evidence::Genesis;

            // Some random timestamps:
            let mut t = <[u64; N]>::arbitrary(u)?;

            // Randomly populated sequence of actions:
            let mut actions: Vec<Action<Timestamp>> = Vec::new();

            let mut i = 0;
            while i < t.len() {
                let a = match u8::arbitrary(u)? {
                    0 => Action::ResetTimer(Round::new(0, 0)),
                    1 => Action::Catchup(Round::new(0, 0)),
                    2 => Action::Gc(Round::new(0, 0)),
                    _ => {
                        let n = t[i];
                        i += 1;
                        Action::Deliver(Payload::new(r, k, n.into(), e.clone()))
                    }
                };
                actions.push(a)
            }

            let mut ct = ConsensusTime(Default::default());
            tick(&actions, &mut ct);

            // Find the length of the last deliver actions segment:
            let n = actions
                .iter()
                .rev()
                .skip_while(|a| !a.is_deliver())
                .take_while(|a| a.is_deliver())
                .count();

            let m = math::median(&mut t[N - n..]).unwrap_or(0);
            assert_eq!(ct.0, m.into());

            Ok(())
        })
        .size_min(512);
    }
}
