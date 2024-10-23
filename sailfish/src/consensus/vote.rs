use std::collections::BTreeMap;

use bitvec::{bitvec, vec::BitVec};
use committable::Committable;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use tracing::warn;

use crate::types::{certificate::Certificate, envelope::Envelope, PublicKey, Signature};

use super::committee::StaticCommittee;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct VoteAccumulator<D: Committable> {
    committee: StaticCommittee,
    votes: BTreeMap<PublicKey, Envelope<D>>,
    signers: (BitVec, Vec<Signature>),
}

impl<D: Committable + Clone> VoteAccumulator<D> {
    pub fn new(committee: StaticCommittee) -> Self {
        Self {
            votes: BTreeMap::new(),
            signers: (bitvec![0; committee.total_nodes()], Vec::new()),
            committee,
        }
    }

    pub fn accumulate(&mut self, vote: Envelope<D>) -> Option<Certificate<D>> {
        if self.votes.contains_key(vote.signing_key()) {
            return None;
        }

        if !vote.is_valid(&self.committee) {
            warn!("invalid vote signature");
            return None;
        }

        let Some(index) = self
            .committee
            .committee()
            .iter()
            .position(|k| k == vote.signing_key())
        else {
            return None;
        };

        self.signers.0.set(index, true);
        self.signers.1.push(vote.signature().clone());

        self.votes.insert(vote.signing_key().clone(), vote.clone());

        if self.votes.len() < self.committee.success_threshold().get() as usize {
            return None;
        }

        let pp = <PublicKey as SignatureKey>::public_parameter(
            self.committee.stake_table(),
            U256::from(self.committee.success_threshold().get()),
        );

        let sig = <PublicKey as SignatureKey>::assemble(&pp, &self.signers.0, &self.signers.1);

        Some(Certificate::new(vote.into_data(), sig))
    }

    pub fn vote(&self, from: &PublicKey) -> Option<&D> {
        self.votes.get(from).map(|env| env.data())
    }
}
