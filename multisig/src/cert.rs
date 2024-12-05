use std::collections::BTreeMap;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{Committee, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Certificate<D: Committable> {
    data: D,
    commitment: Commitment<D>,
    signatures: BTreeMap<u8, Signature>,
}

impl<D: Committable> Certificate<D> {
    pub(crate) fn new(data: D, commit: Commitment<D>, sigs: BTreeMap<u8, Signature>) -> Self {
        Self {
            data,
            commitment: commit,
            signatures: sigs,
        }
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn into_data(self) -> D {
        self.data
    }

    pub fn commitment(&self) -> &Commitment<D> {
        &self.commitment
    }

    pub fn is_valid(&self, committee: &Committee) -> bool {
        let n: usize = self
            .signatures
            .iter()
            .map(|(i, s)| {
                let Some(k) = committee.get_key(*i) else {
                    return 0;
                };
                k.is_valid(self.commitment.as_ref(), s) as usize
            })
            .sum();

        n >= committee.quorum_size().get()
    }

    pub(crate) fn signatures(&self) -> &BTreeMap<u8, Signature> {
        &self.signatures
    }
}

impl<D: Committable + Sync> Certificate<D> {
    pub fn is_valid_par(&self, committee: &Committee) -> bool {
        use rayon::prelude::*;

        let n: usize = self
            .signatures
            .par_iter()
            .map(|(i, s)| {
                let Some(k) = committee.get_key(*i) else {
                    return 0;
                };
                k.is_valid(self.commitment.as_ref(), s) as usize
            })
            .sum();

        n >= committee.quorum_size().get()
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
