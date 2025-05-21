use std::collections::BTreeMap;
use std::iter;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use constant_time_eq::constant_time_eq;
use either::Either;
use serde::{Deserialize, Serialize};

use crate::{Committee, CommitteeSeq, Indexed, InvalidSignature, KeyId, PublicKey, Signature};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Certificate<D: Committable> {
    data: D,
    commitment: Commitment<D>,
    signatures: BTreeMap<KeyId, Signature>,
}

impl<D: Committable> Certificate<D> {
    pub(crate) fn new(data: D, commit: Commitment<D>, sigs: BTreeMap<KeyId, Signature>) -> Self {
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

    pub(crate) fn signatures(&self) -> &BTreeMap<KeyId, Signature> {
        &self.signatures
    }
}

impl<D: Committable + Indexed> Certificate<D> {
    pub fn signers<'a>(
        &'a self,
        comm: &'a CommitteeSeq<D::Index>,
    ) -> impl Iterator<Item = &'a PublicKey> {
        let Some(c) = comm.get(self.data.index()) else {
            return Either::Left(iter::empty());
        };
        Either::Right(self.signatures.keys().copied().filter_map(|i| c.get_key(i)))
    }

    pub fn is_valid<'a>(
        &self,
        seq: &'a CommitteeSeq<D::Index>,
    ) -> Result<&'a Committee, InvalidSignature> {
        let Some(c) = seq.get(self.data.index()) else {
            return Err(InvalidSignature(()));
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

        if d && n >= c.quorum_size().get() {
            Ok(c)
        } else {
            Err(InvalidSignature(()))
        }
    }
}

impl<D: Committable + Indexed + Sync> Certificate<D> {
    pub fn is_valid_par<'a>(
        &self,
        seq: &'a CommitteeSeq<D::Index>,
    ) -> Result<&'a Committee, InvalidSignature> {
        use rayon::prelude::*;

        let Some(c) = seq.get(self.data.index()) else {
            return Err(InvalidSignature(()));
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

        if d && n >= c.quorum_size().get() {
            Ok(c)
        } else {
            Err(InvalidSignature(()))
        }
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
