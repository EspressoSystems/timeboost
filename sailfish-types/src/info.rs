use std::fmt;

use crate::RoundNumber;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitteeId(u64);

impl CommitteeId {
    pub const fn new(n: u64) -> Self {
        Self(n)
    }
}

impl From<u64> for CommitteeId {
    fn from(n: u64) -> Self {
        Self(n)
    }
}

impl From<CommitteeId> for u64 {
    fn from(id: CommitteeId) -> Self {
        id.0
    }
}

impl fmt::Display for CommitteeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitteeInfo {
    id: CommitteeId,
    round: RoundNumber,
}

impl CommitteeInfo {
    pub fn new<C, N>(id: C, r: N) -> Self
    where
        C: Into<CommitteeId>,
        N: Into<RoundNumber>,
    {
        Self {
            id: id.into(),
            round: r.into(),
        }
    }

    pub fn id(&self) -> CommitteeId {
        self.id
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }
}

impl fmt::Display for CommitteeInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ id := {}, round := {} }}", self.id, self.round)
    }
}

impl Committable for CommitteeInfo {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CommitteeInfo")
            .u64_field("id", self.id.into())
            .u64_field("round", self.round.into())
            .finalize()
    }
}
