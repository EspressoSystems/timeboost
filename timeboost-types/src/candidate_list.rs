use std::sync::Arc;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{Bundle, DelayedInboxIndex, Epoch, PriorityBundle, Timestamp, bundle::Signed};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidateList(Arc<Inner>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "CandidateList")]
struct Inner {
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<PriorityBundle<Signed>>,
    regular: Vec<Bundle>,
}

#[derive(Debug)]
pub struct Builder {
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<PriorityBundle<Signed>>,
    regular: Vec<Bundle>,
}

impl Builder {
    pub fn with_priority_bundles(mut self, t: Vec<PriorityBundle<Signed>>) -> Self {
        self.priority = t;
        self
    }

    pub fn with_regular_bundles(mut self, t: Vec<Bundle>) -> Self {
        self.regular = t;
        self
    }

    pub fn finish(self) -> CandidateList {
        CandidateList(Arc::new(Inner {
            time: self.time,
            index: self.index,
            priority: self.priority,
            regular: self.regular,
        }))
    }
}

impl CandidateList {
    pub fn builder<N>(t: Timestamp, i: N) -> Builder
    where
        N: Into<DelayedInboxIndex>,
    {
        Builder {
            time: t,
            index: i.into(),
            regular: Vec::new(),
            priority: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.regular.is_empty() && self.0.priority.is_empty()
    }

    pub fn has_priority_bundles(&self) -> bool {
        !self.0.priority.is_empty()
    }

    pub fn epoch(&self) -> Epoch {
        self.0.time.epoch()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.0.time
    }

    pub fn len(&self) -> usize {
        self.0.regular.len() + self.0.priority.len()
    }

    pub fn into_bundles(self) -> (Vec<PriorityBundle<Signed>>, Vec<Bundle>) {
        match Arc::try_unwrap(self.0) {
            Ok(inner) => (inner.priority, inner.regular),
            Err(arc) => (arc.priority.clone(), arc.regular.clone()),
        }
    }

    pub fn regular_bundles(&self) -> &[Bundle] {
        &self.0.regular
    }

    pub fn priority_bundles(&self) -> &[PriorityBundle<Signed>] {
        &self.0.priority
    }

    pub fn delayed_inbox_index(&self) -> DelayedInboxIndex {
        self.0.index
    }
}

impl Committable for CandidateList {
    fn commit(&self) -> Commitment<Self> {
        let mut builder = RawCommitmentBuilder::new("CandidateList")
            .u64_field("time", self.0.time.into())
            .u64_field("index", self.0.index.into())
            .u64_field("priority", self.0.priority.len() as u64)
            .u64_field("regular", self.0.priority.len() as u64);
        builder = self
            .0
            .priority
            .iter()
            .fold(builder, |b, pb| b.var_size_bytes(pb.commit().as_ref()));
        builder = builder.u64_field("regular", self.regular_bundles().len() as u64);
        self.0
            .regular
            .iter()
            .fold(builder, |b, rb| b.var_size_bytes(rb.commit().as_ref()))
            .finalize()
    }
}
