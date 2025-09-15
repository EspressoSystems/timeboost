use std::{collections::BTreeMap, num::NonZeroUsize};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use constant_time_eq::constant_time_eq;
use minicbor::{CborLen, Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{Committee, KeyId, PublicKey, Signature};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    CborLen,
)]
#[cbor(map)]
pub struct Certificate<D: Committable> {
    #[cbor(n(0))]
    data: D,

    #[cbor(n(1), with = "adapters::commitment")]
    commitment: Commitment<D>,

    #[cbor(n(2))]
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

    pub fn signers<'a>(&'a self, comm: &'a Committee) -> impl Iterator<Item = &'a PublicKey> {
        self.signatures
            .keys()
            .copied()
            .filter_map(|i| comm.get_key(i))
    }

    pub fn is_valid(&self, committee: &Committee) -> bool {
        self.is_valid_with_threshold(committee, committee.quorum_size())
    }

    pub fn is_valid_with_threshold(&self, committee: &Committee, t: NonZeroUsize) -> bool {
        let d = constant_time_eq(self.data.commit().as_ref(), self.commitment.as_ref());
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

        d && n >= t.get()
    }

    pub(crate) fn signatures(&self) -> &BTreeMap<KeyId, Signature> {
        &self.signatures
    }
}

impl<D: Committable + Sync> Certificate<D> {
    pub fn is_valid_par(&self, committee: &Committee) -> bool {
        self.is_valid_with_threshold_par(committee, committee.quorum_size())
    }

    pub fn is_valid_with_threshold_par(&self, committee: &Committee, t: NonZeroUsize) -> bool {
        use rayon::prelude::*;

        let d = constant_time_eq(self.data.commit().as_ref(), self.commitment.as_ref());

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

        d && n >= t.get()
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
