use std::ops::Deref;

use alloy_primitives::B256;
use bytes::Bytes;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, CommitteeId};
use sailfish_types::{Evidence, RoundNumber};
use serde::{Deserialize, Serialize};
use timeboost_proto::block as proto;

#[derive(
    Debug, Default, Clone, Copy, Serialize, Deserialize, Ord, PartialOrd, PartialEq, Eq, Hash,
)]
pub struct BlockHash(B256);

impl From<[u8; 32]> for BlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }
}

impl Deref for BlockHash {
    type Target = B256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Committable for BlockHash {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("BlockHash")
            .fixed_size_field("block-hash", &self.0)
            .finalize()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct NamespaceId(u32);

impl From<u32> for NamespaceId {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<NamespaceId> for u32 {
    fn from(val: NamespaceId) -> Self {
        val.0
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    namespace: NamespaceId,
    round: RoundNumber,
    hash: BlockHash,
    payload: Bytes,
    evidence: Evidence,
}

impl Block {
    pub fn new<N, R>(n: N, r: R, h: BlockHash, p: Bytes, e: Evidence) -> Self
    where
        N: Into<NamespaceId>,
        R: Into<RoundNumber>,
    {
        Self {
            namespace: n.into(),
            round: r.into(),
            hash: h,
            payload: p,
            evidence: e,
        }
    }

    pub fn namespace(&self) -> NamespaceId {
        self.namespace
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid block: {0}")]
pub struct InvalidBlock(&'static str);

impl TryFrom<proto::Block> for Block {
    type Error = InvalidBlock;

    fn try_from(b: proto::Block) -> Result<Self, Self::Error> {
        let h: [u8; 32] = b
            .hash
            .try_into()
            .map_err(|_| InvalidBlock("block hash != 32 bytes"))?;

        Ok(Self {
            namespace: NamespaceId(b.namespace),
            round: b.round.into(),
            hash: BlockHash::from(h),
            payload: b.payload,
            evidence: {
                let cfg = bincode::config::standard();
                bincode::serde::decode_from_slice(&b.evidence, cfg)
                    .map(|(e, _)| e)
                    .map_err(|_| InvalidBlock("failed to decode block evidence"))?
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockInfo {
    round: RoundNumber,
    hash: BlockHash,
    committee: CommitteeId,
}

impl BlockInfo {
    pub fn new<R, C>(r: R, hash: BlockHash, committee: C) -> Self
    where
        R: Into<RoundNumber>,
        C: Into<CommitteeId>,
    {
        Self {
            round: r.into(),
            hash,
            committee: committee.into(),
        }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }

    pub fn committee(&self) -> CommitteeId {
        self.committee
    }
}

impl Committable for BlockInfo {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("BlockInfo")
            .field("round", self.round.commit())
            .field("hash", self.hash.commit())
            .field("committee", self.committee.commit())
            .finalize()
    }
}

pub struct CertifiedBlock {
    data: Block,
    cert: Certificate<BlockInfo>,
}

impl CertifiedBlock {
    pub fn new(cert: Certificate<BlockInfo>, data: Block) -> Self {
        Self { cert, data }
    }

    pub fn cert(&self) -> &Certificate<BlockInfo> {
        &self.cert
    }

    pub fn data(&self) -> &Block {
        &self.data
    }
}
