use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use committable::Committable;
use committee::StaticCommittee;
use hotshot::types::{BLSPrivKey, BLSPubKey, SignatureKey};
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use tracing::{debug, instrument, trace, warn};
use vote::VoteAccumulator;

use crate::types::{
    block::{Block, BlockPayload, Transaction},
    block_header::BlockHeader,
    certificate::{
        NoVoteCertificate, NoVoteData, TimeoutCertificate, TimeoutData, VertexCertificate,
        VertexCertificateData,
    },
    message::SailfishEvent,
    vertex::Vertex,
    vote::{NoVoteVote, TimeoutVote, VertexVote},
};
pub mod committee;
pub mod vote;

/// The DAG is a mapping of the round number to the vertex and the signature computed over the
/// commitment to the vertex to prove the authenticity of the vertex. Lastly, we include the
/// certificate of the vertex.
pub type Dag = BTreeMap<
    ViewNumber,
    BTreeMap<
        BLSPubKey,
        (
            Vertex,
            <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
        ),
    >,
>;

/// The context of a task, including its public and private keys. The context is passed
/// immutably to the task function.
#[derive(Clone, Debug)]
pub struct TaskContext {
    /// The public key of the node running this task.
    pub public_key: BLSPubKey,

    /// The private key of the node running this task.
    pub private_key: BLSPrivKey,

    /// The ID of the node running this task.
    pub id: u64,

    /// The view number of the node running this task.
    pub round: ViewNumber,
}

/// The core consensus state.
pub struct Consensus {
    /// The context of the node running this task.
    pub context: TaskContext,

    /// The quorum membership.
    pub quorum_membership: StaticCommittee,

    /// The last committed round number.
    pub last_committed_round_number: ViewNumber,

    /// The last proposed round number.
    pub last_proposed_round_number: ViewNumber,

    /// The current round number.
    pub round: ViewNumber,

    /// The uncomitted vertices that we've generated so far.
    pub uncommitted_vertices: BTreeMap<ViewNumber, Vec<Vertex>>,

    /// The map of vertex certificates that we've generated so far. We keep a vector of certificates
    /// for each round to handle getting 2f + 1 certificates for a vertex. To be able to propose, the
    /// vector of certificates must be of length 2f + 1.
    pub vertex_certificates: BTreeMap<ViewNumber, Vec<VertexCertificate>>,

    /// The map of timeout certificates that we've generated so far.
    pub timeout_certificates: BTreeMap<ViewNumber, TimeoutCertificate>,

    /// The map of no vote certificates that we've generated so far.
    pub no_vote_certificates: BTreeMap<ViewNumber, NoVoteCertificate>,

    /// The DAG of vertices
    pub dag: Dag,

    /// The accumulator for the vertices of a given round.
    pub vertex_accumulator_map:
        BTreeMap<ViewNumber, VoteAccumulator<VertexVote, VertexCertificate>>,

    /// The accumulator for the timeouts of a given round.
    pub timeout_accumulator_map:
        BTreeMap<ViewNumber, VoteAccumulator<TimeoutVote, TimeoutCertificate>>,

    /// The accumulator for the no votes of a given round.
    pub no_vote_accumulator_map:
        BTreeMap<ViewNumber, VoteAccumulator<NoVoteVote, NoVoteCertificate>>,

    /// The transactions that this node has accumulated.
    pub transactions: Vec<Transaction>,

    /// All events that this node has seen in its lifetime.
    #[cfg(test)]
    pub events: Vec<SailfishEvent>,
}

pub fn verify_committed_round(
    round: ViewNumber,
    signature: &<BLSPubKey as SignatureKey>::PureAssembledSignatureType,
    quorum_membership: &StaticCommittee,
) -> Result<()> {
    // Make sure that the signature is valid for the provided round.
    ensure!(
        quorum_membership
            .leader(round)
            .validate(signature, round.commit().as_ref()),
        "invalid signature on committed round event"
    );

    Ok(())
}

impl Consensus {
    pub fn new(context: TaskContext, quorum_membership: StaticCommittee) -> Self {
        Self {
            context,
            quorum_membership,
            last_committed_round_number: ViewNumber::genesis(),
            last_proposed_round_number: ViewNumber::genesis(),
            round: ViewNumber::genesis(),
            uncommitted_vertices: BTreeMap::new(),
            vertex_certificates: BTreeMap::new(),
            timeout_certificates: BTreeMap::new(),
            no_vote_certificates: BTreeMap::new(),
            dag: Dag::new(),
            vertex_accumulator_map: BTreeMap::new(),
            timeout_accumulator_map: BTreeMap::new(),
            no_vote_accumulator_map: BTreeMap::new(),
            transactions: Vec::new(),
            #[cfg(test)]
            events: Vec::new(),
        }
    }

    pub fn round(&self) -> ViewNumber {
        self.round
    }

    #[instrument(
        skip(self),
        fields(event = %event, round = %self.round, id = %self.context.id),
    )]
    pub async fn handle_event(&mut self, event: SailfishEvent) -> Result<Vec<SailfishEvent>> {
        #[cfg(test)]
        {
            self.events.push(event.clone());
        }

        match event {
            SailfishEvent::VertexRecv(vertex, signature) => {
                self.handle_vertex_recv(vertex, signature).await
            }
            SailfishEvent::VertexVoteRecv(vote) => self.handle_vertex_vote_recv(vote).await,
            SailfishEvent::TimeoutRecv(round) => self.handle_timeout_recv(round).await,
            SailfishEvent::NoVoteRecv(round) => self.handle_no_vote_recv(round).await,
            SailfishEvent::TimeoutVoteRecv(vote) => self.handle_timeout_vote_recv(vote).await,
            SailfishEvent::NoVoteVoteRecv(vote) => self.handle_no_vote_vote_recv(vote).await,
            SailfishEvent::VertexCommitted(round, signature) => {
                self.handle_vertex_committed(round, signature)
            }
            SailfishEvent::RoundChange(round) => self.handle_round_change(round),
            SailfishEvent::VertexCertificateRecv(cert) => self.handle_vertex_certificate_recv(cert),
            _ => Ok(vec![]),
        }
    }

    pub fn last_committed_round_number(&self) -> ViewNumber {
        self.last_committed_round_number
    }

    #[instrument(
        skip_all,
        fields(vertex = %vertex, round = %self.round, id = %self.context.id)
    )]
    async fn handle_vertex_recv(
        &mut self,
        vertex: Vertex,
        signature: <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
    ) -> Result<Vec<SailfishEvent>> {
        let round = vertex.round;

        debug!(
            "Received a vertex for round: {}, voting for round: {}",
            round,
            round + 1
        );

        // TODO: Validation

        // Record the vertex in the DAG.
        self.dag
            .entry(round)
            .or_default()
            // TODO: this is a heavy clone
            .insert(self.context.public_key, (vertex.clone(), signature));

        // Assuming that the vertex is valid, we can now submit our vote for the vertex.
        let vote = VertexVote::create_signed_vote(
            VertexCertificateData {
                round,
                source: vertex.source,
            },
            self.context.public_key,
            &self.context.private_key,
        )?;

        // This is a valid vertex, so we vote for it and change our round to the next round.
        let output_events = vec![SailfishEvent::VertexVoteSend(vote)];
        Ok(output_events)
    }

    #[instrument(
        skip_all,
        fields(round = %self.round, id = %self.context.id, vote = %vote.round_number())
    )]
    async fn handle_vertex_vote_recv(&mut self, vote: VertexVote) -> Result<Vec<SailfishEvent>> {
        let round = vote.round_number();

        // TODO: Validation

        // Check if we have an accumulator for this round.
        if let std::collections::btree_map::Entry::Vacant(e) =
            self.vertex_accumulator_map.entry(round)
        {
            let accumulator = VoteAccumulator::new(&vote, &self.quorum_membership).await;
            e.insert(accumulator);
        }

        // Add the vote to the accumulator.
        if let Some(cert) = self
            .vertex_accumulator_map
            .get_mut(&round)
            .unwrap()
            .accumulate(&vote, &self.quorum_membership)
            .await
        {
            self.vertex_certificates
                .entry(round)
                .or_default()
                .push(cert.clone());

            self.vertex_accumulator_map =
                self.vertex_accumulator_map.split_off(&vote.round_number());

            Ok(vec![SailfishEvent::VertexCertificateSend(cert)])
        } else {
            Ok(vec![])
        }
    }

    /// Handles the internal timeout event, transforming it into an external timeout vote event.
    ///
    /// This method is responsible for handling the internal timeout event, which is triggered when a
    /// timeout occurs. This event triggers the node to vote to timeout for the given round.
    async fn handle_timeout_recv(&mut self, round: ViewNumber) -> Result<Vec<SailfishEvent>> {
        ensure!(self.round < round, "Received timeout for an old round");

        // We made it past the round check, let's vote to timeout.
        let vote = TimeoutVote::create_signed_vote(
            TimeoutData { round },
            self.context.public_key,
            &self.context.private_key,
        )?;

        Ok(vec![SailfishEvent::TimeoutVoteSend(vote)])
    }

    /// Handles the internal no vote event, transforming it into an external no vote vote event.
    async fn handle_no_vote_recv(&mut self, round: ViewNumber) -> Result<Vec<SailfishEvent>> {
        ensure!(self.round < round, "Received no vote for an old round");

        // We made it past the round check, let's vote to no vote.
        let vote = NoVoteVote::create_signed_vote(
            NoVoteData { round },
            self.context.public_key,
            &self.context.private_key,
        )?;

        Ok(vec![SailfishEvent::NoVoteVoteSend(vote)])
    }

    async fn handle_timeout_vote_recv(&mut self, vote: TimeoutVote) -> Result<Vec<SailfishEvent>> {
        // TODO: Validation

        let round = vote.round_number();

        // Check if we have an accumulator for this round.
        if let std::collections::btree_map::Entry::Vacant(e) =
            self.timeout_accumulator_map.entry(round)
        {
            let accumulator = VoteAccumulator::new(&vote, &self.quorum_membership).await;
            e.insert(accumulator);
        }

        // Add the vote to the accumulator.
        if let Some(cert) = self
            .timeout_accumulator_map
            .get_mut(&round)
            .unwrap()
            .accumulate(&vote, &self.quorum_membership)
            .await
        {
            // If we get threshold for a vertex, then we can generate a certificate for it. This will
            // go into the set of certificates that we've generated so far for valid vertices, and will
            // form the basis of our parent set when we create our next vertex.
            self.timeout_certificates.entry(round).or_insert(cert);

            // Remove the old accumulators for prior views.
            self.timeout_accumulator_map =
                self.timeout_accumulator_map.split_off(&vote.round_number());
        }

        Ok(vec![])
    }

    async fn handle_no_vote_vote_recv(&mut self, vote: NoVoteVote) -> Result<Vec<SailfishEvent>> {
        // TODO: Validation

        let round = vote.round_number();

        // Check if we have an accumulator for this round.
        if let std::collections::btree_map::Entry::Vacant(e) =
            self.no_vote_accumulator_map.entry(round)
        {
            let accumulator = VoteAccumulator::new(&vote, &self.quorum_membership).await;
            e.insert(accumulator);
        }

        //tchd the vote to the accumulator.
        if let Some(cert) = self
            .no_vote_accumulator_map
            .get_mut(&round)
            .unwrap()
            .accumulate(&vote, &self.quorum_membership)
            .await
        {
            // If we get threshold for a vertex, then we can generate a certificate for it. This will
            // go into the set of certificates that we've generated so far for valid vertices, and will
            // form the basis of our parent set when we create our next vertex.
            self.no_vote_certificates.entry(round).or_insert(cert);

            // Remove the old accumulators for prior views.
            self.no_vote_accumulator_map =
                self.no_vote_accumulator_map.split_off(&vote.round_number());
        }

        Ok(vec![])
    }

    fn handle_vertex_committed(
        &mut self,
        round: ViewNumber,
        signature: <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
    ) -> Result<Vec<SailfishEvent>> {
        verify_committed_round(round, &signature, &self.quorum_membership)?;

        // Split off the uncommitted vertices for the next round, removing stragglers from prior rounds..
        self.uncommitted_vertices = self.uncommitted_vertices.split_off(&round);

        self.last_committed_round_number = round;
        Ok(vec![])
    }

    fn handle_round_change(&mut self, round: ViewNumber) -> Result<Vec<SailfishEvent>> {
        if round <= self.round {
            // trace!(
            //     "Received round change for a prior round; ignoring: {} <= {}",
            //     round,
            //     self.round
            // );
            return Ok(vec![]);
        }

        self.round = round;
        Ok(vec![])
    }

    #[instrument(
        skip_all,
        fields(id = self.context.id, round = %self.round, last_proposed_round_number = %self.last_proposed_round_number)
    )]
    fn handle_vertex_certificate_recv(
        &mut self,
        cert: VertexCertificate,
    ) -> Result<Vec<SailfishEvent>> {
        let mut output_events = vec![];
        let round = cert.round_number();

        if round < self.last_proposed_round_number {
            trace!(
                "Received a vertex certificate for a prior round; ignoring: {} < {}",
                round,
                self.last_proposed_round_number
            );
            return Ok(vec![]);
        }

        // TODO: Validation

        // TODO: Make sure that the vertex certificate data contains a vertex that we've generated.

        // Add the certificate to the set of certificates that we've received so far.
        self.vertex_certificates
            .entry(round)
            .or_default()
            .push(cert);

        // If we have certs for this, then let's see if we can initiate a proposal.
        let Some(certs) = self.vertex_certificates.get(&round) else {
            return Ok(vec![]);
        };
        let n_certs = certs.len() as u64;

        // Are we at threshold for any of the certificates that we've received so far?
        let thresh: u64 = self.quorum_membership.success_threshold().into();
        if n_certs >= thresh {
            // Do we have a timeout certificate?
            let timeout_certificate = self.timeout_certificates.get(&round).cloned();

            // Do we have a no vote certificate?
            let no_vote_certificate = self.no_vote_certificates.get(&round).cloned();

            // If we're the leader, we can commit our prior vertex, if it's genesis, we don't have a prior vertex.
            if self.quorum_membership.leader(round) == self.context.public_key
                && self.round != ViewNumber::genesis()
            {
                // This should never happen, but it's very bad if it does.
                let Some(vertex) = self
                    .uncommitted_vertices
                    .get(&round)
                    .and_then(|v| v.first())
                else {
                    return Ok(vec![]);
                };

                let vertex_commitment = vertex.commit();

                // Sign over the vertex commitment.
                let signature =
                    BLSPubKey::sign(&self.context.private_key, vertex_commitment.as_ref())
                        .context("failed to sign the vertex commitment")?;

                // Send the commitment to the network for the prior round.
                output_events.push(SailfishEvent::VertexCommitted(vertex.round, signature));
            }

            // Yes, so we can generate a new vertex.
            let vertex = Vertex {
                round: self.round + 1,
                source: self.context.public_key,
                // TODO: Fill in the block
                block: Block {
                    header: BlockHeader {},
                    payload: BlockPayload {
                        transactions: self.transactions.clone(),
                    },
                },
                parents: certs.clone(),
                no_vote_certificate,
                timeout_certificate,
            };

            debug!(
                "Submitting a vertex for round {} to the network",
                vertex.round
            );

            // Compute a signature to the commitment of the vertex.
            let vertex_commitment = vertex.commit();
            let signature = BLSPubKey::sign(&self.context.private_key, vertex_commitment.as_ref())
                .context("failed to sign the vertex commitment")?;

            // Make sure we don't double-propose for a given round.
            self.last_proposed_round_number = vertex.round;

            debug!(
                "Last proposed round number is now {}",
                self.last_proposed_round_number
            );

            // Move to the next round.
            output_events.push(SailfishEvent::RoundChange(vertex.round));

            // Submit the vertex to the network.
            output_events.push(SailfishEvent::VertexSend(vertex, signature));
        }

        Ok(output_events)
    }
}
