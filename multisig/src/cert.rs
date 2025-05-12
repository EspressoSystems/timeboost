use std::collections::BTreeMap;
use std::iter;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use constant_time_eq::constant_time_eq;
use either::Either;
use serde::{Deserialize, Serialize};

use crate::{Committee, KeyId, PublicKey, Signature, Versioned};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Certificate<D: Committable> {
    data: Versioned<D>,
    commitment: Commitment<Versioned<D>>,
    signatures: BTreeMap<KeyId, Signature>,
}

impl<D: Committable> Certificate<D> {
    pub(crate) fn new(
        data: Versioned<D>,
        commit: Commitment<Versioned<D>>,
        sigs: BTreeMap<KeyId, Signature>,
    ) -> Self {
        Self {
            data,
            commitment: commit,
            signatures: sigs,
        }
    }

    pub fn data(&self) -> &Versioned<D> {
        &self.data
    }

    pub fn into_data(self) -> Versioned<D> {
        self.data
    }

    pub fn commitment(&self) -> &Commitment<Versioned<D>> {
        &self.commitment
    }

    pub fn signers(&self, comm: &Committee) -> impl Iterator<Item = PublicKey> {
        let Some(c) = comm.at(self.data().version()) else {
            return Either::Left(iter::empty());
        };
        Either::Right(
            self.signatures
                .keys()
                .copied()
                .filter_map(move |i| c.get_key(i).copied()),
        )
    }

    pub fn is_valid(&self, committee: &Committee) -> bool {
        let Some(c) = committee.at(self.data().version()) else {
            return false;
        };

        let d = constant_time_eq(self.data.commit().as_ref(), self.commitment.as_ref());

        let n: usize = self
            .signatures
            .iter()
            .map(|(i, s)| {
                let Some(k) = c.get_key(*i) else {
                    return 0;
                };
                k.is_valid(self.commitment.as_ref(), s) as usize
            })
            .sum();

        d && n >= c.quorum_size().get()
    }

    pub(crate) fn signatures(&self) -> &BTreeMap<KeyId, Signature> {
        &self.signatures
    }
}

impl<D: Committable + Sync> Certificate<D> {
    pub fn is_valid_par(&self, committee: &Committee) -> bool {
        use rayon::prelude::*;

        let Some(c) = committee.at(self.data().version()) else {
            return false;
        };

        let d = constant_time_eq(self.data.commit().as_ref(), self.commitment.as_ref());

        let n: usize = self
            .signatures
            .par_iter()
            .map(|(i, s)| {
                let Some(k) = c.get_key(*i) else {
                    return 0;
                };
                k.is_valid(self.commitment.as_ref(), s) as usize
            })
            .sum();

        d && n >= c.quorum_size().get()
    }
}

impl<D: Committable> Committable for Certificate<D> {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Certificate")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .u64_field("quorum", self.signatures.len() as u64);
        self.signatures
            .iter()
            .fold(builder, |b, (&i, s)| {
                b.u64_field("index", i.into()).field("sig", s.commit())
            })
            .finalize()
    }
}
