use std::collections::{BTreeMap, HashMap};
use std::iter;

use committable::{Commitment, Committable};
use either::Either;

use crate::{Certificate, Committee, PublicKey, Signature, Signed};

#[derive(Debug, Clone)]
pub struct VoteAccumulator<D: Committable> {
    committee: Committee,
    votes: HashMap<Commitment<D>, Entry<D>>,
    cert: Option<Certificate<D>>,
}

#[derive(Debug, Clone)]
struct Entry<D> {
    data: D,
    sigs: BTreeMap<u8, Signature>,
}

impl<D> Entry<D> {
    fn new(data: D) -> Self {
        Self {
            data,
            sigs: BTreeMap::new(),
        }
    }
}

impl<D: Committable + Clone> VoteAccumulator<D> {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            votes: HashMap::new(),
            cert: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    pub fn votes(&self, c: &Commitment<D>) -> usize {
        self.votes.get(c).map(|e| e.sigs.len()).unwrap_or(0)
    }

    pub fn voters(&self, c: &Commitment<D>) -> impl Iterator<Item = &PublicKey> {
        if let Some(e) = self.votes.get(c) {
            Either::Right(e.sigs.keys().filter_map(|i| self.committee.get_key(*i)))
        } else {
            Either::Left(iter::empty())
        }
    }

    pub fn certificate(&self) -> Option<&Certificate<D>> {
        self.cert.as_ref()
    }

    pub fn into_certificate(self) -> Option<Certificate<D>> {
        self.cert
    }

    pub fn set_certificate(&mut self, c: Certificate<D>) {
        self.clear();
        self.votes.insert(
            *c.commitment(),
            Entry {
                data: c.data().clone(),
                sigs: c.signatures().clone(),
            },
        );
        self.cert = Some(c)
    }

    pub fn clear(&mut self) {
        self.votes.clear();
        self.cert = None
    }

    pub fn add(&mut self, signed: Signed<D>) -> Result<Option<&Certificate<D>>, Error> {
        let Some(ix) = self.committee.get_index(signed.signing_key()) else {
            return Err(Error::UnknownSigningKey);
        };

        let commit = signed.commitment();
        let sig = *signed.signature();

        let entry = self
            .votes
            .entry(commit)
            .or_insert_with(|| Entry::new(signed.into_data()));

        if entry.sigs.contains_key(&ix) {
            return Ok(self.certificate());
        }

        entry.sigs.insert(ix, sig);

        if entry.sigs.len() < self.committee.quorum_size().get() {
            return Ok(None);
        }

        let crt = Certificate::new(entry.data.clone(), commit, entry.sigs.clone());
        self.cert = Some(crt);

        Ok(self.certificate())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("unknown signing key")]
    UnknownSigningKey,
}
