use core::fmt;
use std::{
    collections::HashMap,
    marker::PhantomData,
    ops::{Add, Deref, Sub},
};

use bytes::Bytes;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, Committee, CommitteeId, Unchecked, Validated};
use multisig::{KeyId, Signature};
use sailfish_types::{Round, RoundNumber};
use serde::{Deserialize, Serialize};
use timeboost_proto::certified_block as proto;

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
pub struct BlockHash([u8; 32]);

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

    pub fn to_protobuf(&self) -> proto::CertifiedBlock {
        proto::CertifiedBlock {
            block: Some(proto::Block {
                round: self.data.round.into(),
                payload: self.data.payload.clone(),
            }),
            cert: Some(proto::Certificate {
                info: Some(proto::BlockInfo {
                    block_number: self.cert.data().num.into(),
                    round_number: self.cert.data().round.num().into(),
                    committee_id: self.cert.data().round.committee().into(),
                    block_hash: self.cert.data().hash.to_vec(),
                }),
                commitment: Vec::from(<[u8; 32]>::from(*self.cert.commitment())),
                signatures: self
                    .cert
                    .entries()
                    .map(|(k, s)| (u32::from(k), s.to_bytes().to_vec()))
                    .collect(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{ctx}: failed to convert from protobuf: {err}")]
pub struct ProtobufError {
    ctx: &'static str,
    err: Box<dyn std::error::Error + Send + Sync>,
}

impl TryFrom<proto::CertifiedBlock> for CertifiedBlock<Unchecked> {
    type Error = ProtobufError;

    fn try_from(p: proto::CertifiedBlock) -> Result<Self, Self::Error> {
        let block = p.block.ok_or_else(|| ProtobufError {
            ctx: "block",
            err: "missing".into(),
        })?;

        let cert = p.cert.ok_or_else(|| ProtobufError {
            ctx: "cert",
            err: "missing".into(),
        })?;

        let info = cert.info.ok_or_else(|| ProtobufError {
            ctx: "info",
            err: "missing".into(),
        })?;

        let block_info = BlockInfo {
            num: info.block_number.into(),
            round: Round::new(info.round_number, info.committee_id),
            hash: BlockHash(info.block_hash.try_into().map_err(|_| ProtobufError {
                ctx: "block hash",
                err: "invalid len".into(),
            })?),
        };

        let signatures: HashMap<KeyId, Signature> = cert
            .signatures
            .into_iter()
            .map(|(k, s)| {
                let s = Signature::try_from(&s[..]).map_err(|e| ProtobufError {
                    ctx: "signature",
                    err: e.into(),
                })?;
                let k = u8::try_from(k).map_err(|e| ProtobufError {
                    ctx: "key id",
                    err: e.into(),
                })?;
                Ok((k.into(), s))
            })
            .collect::<Result<_, ProtobufError>>()?;

        let commitment: Commitment<BlockInfo> = <[u8; 32]>::try_from(&*cert.commitment)
            .map(Commitment::from_raw)
            .map_err(|e| ProtobufError {
                ctx: "commitment",
                err: Box::new(e),
            })?;

        Ok(Self {
            data: Block {
                round: block.round.into(),
                payload: block.payload,
            },
            cert: Certificate::from_parts(block_info, commitment, signatures),
            leader: false,
            _marker: PhantomData,
        })
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
