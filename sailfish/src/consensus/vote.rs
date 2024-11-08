use std::collections::BTreeMap;

use bitvec::{bitvec, vec::BitVec};
use committable::Committable;
use ethereum_types::U256;
use hotshot::types::SignatureKey;

use timeboost_core::types::{
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    PublicKey, Signature,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct VoteAccumulator<D: Committable> {
    committee: StaticCommittee,
    votes: BTreeMap<PublicKey, Envelope<D, Validated>>,
    signers: (BitVec, Vec<Signature>),
    cert: Option<Certificate<D>>,
}

impl<D: Committable + Eq + Clone> VoteAccumulator<D> {
    pub fn new(committee: StaticCommittee) -> Self {
        Self {
            votes: BTreeMap::new(),
            signers: (bitvec![0; committee.size().get()], Vec::new()),
            committee,
            cert: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    pub fn votes(&self) -> usize {
        self.votes.len()
    }

    pub fn clear(&mut self) {
        self.votes.clear();
        self.signers = (bitvec![0; self.committee.size().get()], Vec::new());
        self.cert = None
    }

    pub fn certificate(&self) -> Option<&Certificate<D>> {
        self.cert.as_ref()
    }

    pub fn add(&mut self, vote: Envelope<D, Validated>) -> Result<Option<&Certificate<D>>, Error> {
        if self.votes.contains_key(vote.signing_key()) {
            return Ok(self.certificate());
        }

        let Some(index) = self
            .committee
            .committee()
            .iter()
            .position(|k| k == vote.signing_key())
        else {
            return Err(Error::UnknownSigningKey);
        };

        self.signers.0.set(index, true);
        self.signers.1.push(vote.signature().clone());

        if let Some((_, e)) = self.votes.first_key_value() {
            if e.data() != vote.data() {
                return Err(Error::DataMismatch);
            }
        }

        self.votes.insert(*vote.signing_key(), vote);

        if self.votes.len() < self.committee.quorum_size().get() as usize {
            return Ok(None);
        }

        let pp = <PublicKey as SignatureKey>::public_parameter(
            self.committee.stake_table(),
            U256::from(self.committee.quorum_size().get()),
        );

        let sig = <PublicKey as SignatureKey>::assemble(&pp, &self.signers.0, &self.signers.1);

        let env = self
            .votes
            .first_key_value()
            .expect("non-empty set of votes")
            .1;

        let crt = Certificate::new(env.data().clone(), sig);
        self.cert = Some(crt);
        Ok(self.certificate())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("unknown signing key")]
    UnknownSigningKey,
    #[error("data mismatch")]
    DataMismatch,
}
