use core::fmt;
use std::{
    marker::PhantomData,
    ops::{Add, Deref, Sub},
};

use alloy_primitives::B256;
use bytes::Bytes;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, Committee, CommitteeId, Unchecked, Validated};
use sailfish_types::{Round, RoundNumber};
use serde::{Deserialize, Serialize};

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

impl Default for BlockNumber {
    fn default() -> Self {
        GENESIS_BLOCK
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    round: RoundNumber,
    payload: Bytes,
}

impl Block {
    pub fn new<N>(r: N, p: Bytes) -> Self
    where
        N: Into<RoundNumber>,
    {
        Self {
            round: r.into(),
            payload: p,
        }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn hash(&self) -> BlockHash {
        let mut h = blake3::Hasher::new();
        h.update(&self.round.to_be_bytes());
        h.update(&self.payload);
        BlockHash::from(*h.finalize().as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockInfo {
    num: BlockNumber,
    round: Round,
    hash: BlockHash,
}

impl BlockInfo {
    pub fn new<B>(num: B, r: Round, hash: BlockHash) -> Self
    where
        B: Into<BlockNumber>,
    {
        Self {
            num: num.into(),
            round: r,
            hash,
        }
    }

    pub fn num(&self) -> BlockNumber {
        self.num
    }

    pub fn round(&self) -> &Round {
        &self.round
    }

    pub fn hash(&self) -> &BlockHash {
        &self.hash
    }
}

impl Committable for BlockInfo {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("BlockInfo")
            .field("num", self.num.commit())
            .field("round", self.round.commit())
            .field("hash", self.hash.commit())
            .finalize()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "S: Deserialize<'de>"))]
pub struct CertifiedBlock<S> {
    data: Block,
    cert: Certificate<BlockInfo>,
    #[serde(skip)]
    leader: bool,
    #[serde(skip)]
    _marker: PhantomData<fn(S)>,
}

impl<S> CertifiedBlock<S> {
    pub fn new(cert: Certificate<BlockInfo>, data: Block, leader: bool) -> Self {
        Self {
            cert,
            data,
            leader,
            _marker: PhantomData,
        }
    }

    pub fn committee(&self) -> CommitteeId {
        self.cert.data().round().committee()
    }
}

impl CertifiedBlock<Validated> {
    pub fn is_leader(&self) -> bool {
        self.leader
    }

    pub fn cert(&self) -> &Certificate<BlockInfo> {
        &self.cert
    }

    pub fn data(&self) -> &Block {
        &self.data
    }
}

impl CertifiedBlock<Unchecked> {
    pub fn validated(self, c: &Committee) -> Option<CertifiedBlock<Validated>> {
        if self.data.round == self.cert.data().round.num()
            && self.data.hash() == self.cert.data().hash
            && self.cert.is_valid_par(c)
        {
            Some(CertifiedBlock {
                data: self.data,
                cert: self.cert,
                leader: self.leader,
                _marker: PhantomData,
            })
        } else {
            None
        }
    }
}

impl<S> From<CertifiedBlock<S>> for Certificate<BlockInfo> {
    fn from(block: CertifiedBlock<S>) -> Self {
        block.cert
    }
}

impl<S> From<CertifiedBlock<S>> for Block {
    fn from(block: CertifiedBlock<S>) -> Self {
        block.data
    }
}
