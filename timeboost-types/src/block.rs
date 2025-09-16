use core::fmt;
use std::{
    marker::PhantomData,
    ops::{Add, AddAssign, Deref, Sub},
};

use alloy::primitives::B256;
use bytes::Bytes;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use minicbor::{CborLen, Decode, Encode};
use multisig::{Certificate, Committee, CommitteeId, Unchecked, Validated};
use sailfish_types::{Round, RoundNumber};

/// A timeboost block number.
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode, CborLen,
)]
#[cbor(transparent)]
pub struct BlockNumber(u64);

impl BlockNumber {
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    pub fn u64(&self) -> u64 {
        self.0
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

impl AddAssign<u64> for BlockNumber {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs
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
    Debug, Default, Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Hash, Encode, Decode, CborLen,
)]
#[cbor(transparent)]
pub struct BlockHash(#[cbor(with = "minicbor::bytes")] [u8; 32]);

impl From<[u8; 32]> for BlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Deref for BlockHash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        B256::from(self.0).fmt(f)
    }
}

impl Committable for BlockHash {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("BlockHash")
            .fixed_size_field("block-hash", &self.0)
            .finalize()
    }
}

#[derive(Debug, Clone, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct Block {
    #[cbor(n(0))]
    number: BlockNumber,

    #[cbor(n(1))]
    round: RoundNumber,

    #[cbor(n(2), with = "adapters::bytes")]
    payload: Bytes,
}

impl Block {
    pub fn new<B, N>(n: B, r: N, p: Bytes) -> Self
    where
        B: Into<BlockNumber>,
        N: Into<RoundNumber>,
    {
        Self {
            number: n.into(),
            round: r.into(),
            payload: p,
        }
    }

    pub fn num(&self) -> BlockNumber {
        self.number
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct BlockInfo {
    #[cbor(n(0))]
    num: BlockNumber,

    #[cbor(n(1))]
    round: Round,

    #[cbor(n(2))]
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

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct CertifiedBlock<S> {
    #[cbor(n(0))]
    version: u8,

    #[cbor(n(1))]
    data: Block,

    #[cbor(n(2))]
    cert: Certificate<BlockInfo>,

    #[cbor(skip)]
    leader: bool,

    #[cbor(skip)]
    _marker: PhantomData<fn(&S)>,
}

impl<S> CertifiedBlock<S> {
    pub fn v1(cert: Certificate<BlockInfo>, data: Block, leader: bool) -> Self {
        Self {
            version: 1,
            cert,
            data,
            leader,
            _marker: PhantomData,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
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
            && self
                .cert
                .is_valid_with_threshold_par(c, c.one_honest_threshold())
        {
            Some(CertifiedBlock {
                version: self.version,
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
