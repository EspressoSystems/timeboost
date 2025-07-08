use core::fmt;
use std::ops::{Add, Deref, Sub};

use alloy_primitives::B256;
use bytes::Bytes;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, CommitteeId};
use sailfish_types::RoundNumber;
use serde::{Deserialize, Serialize};
use timeboost_proto::block as proto;

/// The genesis timeboost block number.
pub const GENESIS_BLOCK: BlockNumber = BlockNumber::new(0);

/// A timeboost block number.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockNumber(u64);

impl BlockNumber {
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    pub fn u64(&self) -> u64 {
        self.0
    }

    pub fn genesis() -> Self {
        GENESIS_BLOCK
    }

    pub fn is_genesis(self) -> bool {
        self == GENESIS_BLOCK
    }
}

impl From<u64> for BlockNumber {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<BlockNumber> for u64 {
    fn from(val: BlockNumber) -> Self {
        val.0
    }
}

impl Add<u64> for BlockNumber {
    type Output = BlockNumber;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl Sub<u64> for BlockNumber {
    type Output = BlockNumber;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl Deref for BlockNumber {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Committable for BlockNumber {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Block Number Commitment");
        builder.u64(self.0).finalize()
    }
}

impl fmt::Display for BlockNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
}

impl Block {
    pub fn new<N, R>(n: N, r: R, h: BlockHash, p: Bytes) -> Self
    where
        N: Into<NamespaceId>,
        R: Into<RoundNumber>,
    {
        Self {
            namespace: n.into(),
            round: r.into(),
            hash: h,
            payload: p,
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
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockInfo {
    num: BlockNumber,
    hash: BlockHash,
    committee: CommitteeId,
}

impl BlockInfo {
    pub fn new<B, C>(num: B, hash: BlockHash, committee: C) -> Self
    where
        B: Into<BlockNumber>,
        C: Into<CommitteeId>,
    {
        Self {
            num: num.into(),
            hash,
            committee: committee.into(),
        }
    }

    pub fn num(&self) -> BlockNumber {
        self.num
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
            .field("num", self.num.commit())
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
