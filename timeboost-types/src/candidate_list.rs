use std::ops::Deref;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

use crate::{
    Bundle, DelayedInboxIndex, DkgBundle, Epoch, HasTime, SignedPriorityBundle, Timestamp,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidateList(Arc<Inner>);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "CandidateList")]
struct Inner {
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<SignedPriorityBundle>,
    regular: Vec<Bundle>,
    dkg: Option<DkgBundle>,
}

#[derive(Debug)]
pub struct Builder {
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: Vec<SignedPriorityBundle>,
    regular: Vec<Bundle>,
    dkg: Option<DkgBundle>,
}

impl Builder {
    pub fn with_priority_bundles(mut self, t: Vec<SignedPriorityBundle>) -> Self {
        self.priority = t;
        self
    }

    pub fn with_regular_bundles(mut self, t: Vec<Bundle>) -> Self {
        self.regular = t;
        self
    }

    pub fn with_dkg(mut self, d: Option<DkgBundle>) -> Self {
        self.dkg = d;
        self
    }

    pub fn finish(self) -> CandidateList {
        CandidateList(Arc::new(Inner {
            time: self.time,
            index: self.index,
            priority: self.priority,
            regular: self.regular,
            dkg: self.dkg,
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
            dkg: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.regular.is_empty() && self.0.priority.is_empty()
    }

    pub fn has_priority_bundles(&self) -> bool {
        !self.0.priority.is_empty()
    }

    pub fn epoch(&self) -> Epoch {
        self.0.time.into()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.0.time
    }

    pub fn len(&self) -> usize {
        self.0.regular.len() + self.0.priority.len()
    }

    pub fn into_bundles(self) -> (Vec<SignedPriorityBundle>, Vec<Bundle>, Option<DkgBundle>) {
        match Arc::try_unwrap(self.0) {
            Ok(inner) => (inner.priority, inner.regular, inner.dkg),
            Err(arc) => (arc.priority.clone(), arc.regular.clone(), arc.dkg.clone()),
        }
    }

    pub fn regular_bundles(&self) -> &[Bundle] {
        &self.0.regular
    }

    pub fn priority_bundles(&self) -> &[SignedPriorityBundle] {
        &self.0.priority
    }

    pub fn delayed_inbox_index(&self) -> DelayedInboxIndex {
        self.0.index
    }

    pub fn dkg_bundle(&self) -> Option<DkgBundle> {
        self.0.dkg.clone()
    }
}

impl Committable for CandidateList {
    fn commit(&self) -> Commitment<Self> {
        let mut builder = RawCommitmentBuilder::new("CandidateList")
            .u64_field("time", self.0.time.into())
            .u64_field("index", self.0.index.into())
            .optional("dkg", &self.0.dkg)
            .u64_field("priority", self.0.priority.len() as u64);
        builder = self
            .0
            .priority
            .iter()
            .fold(builder, |b, pb| b.var_size_bytes(pb.digest()));
        builder = builder.u64_field("regular", self.regular_bundles().len() as u64);
        self.0
            .regular
            .iter()
            .fold(builder, |b, rb| b.var_size_bytes(rb.digest()))
            .finalize()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateListBytes(pub Timestamp, pub Bytes);

impl Deref for CandidateListBytes {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl TryFrom<CandidateList> for CandidateListBytes {
    type Error = bincode::error::EncodeError;

    fn try_from(val: CandidateList) -> Result<Self, Self::Error> {
        let time = val.timestamp();
        let mut w = BytesMut::new().writer();
        bincode::serde::encode_into_std_write(val, &mut w, bincode::config::standard())?;
        Ok(CandidateListBytes(time, w.into_inner().freeze()))
    }
}

impl CandidateListBytes {
    pub fn decode<const N: usize>(&self) -> Result<CandidateList, bincode::error::DecodeError> {
        let config = bincode::config::standard().with_limit::<N>();
        let (list, _) = bincode::serde::decode_from_slice(&self.1, config)?;
        Ok(list)
    }
}

impl Committable for CandidateListBytes {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CandidateListBytes")
            .field("time", self.0.commit())
            .var_size_bytes(&self.1)
            .finalize()
    }
}

impl HasTime for CandidateListBytes {
    fn time(&self) -> Timestamp {
        self.0
    }
}
