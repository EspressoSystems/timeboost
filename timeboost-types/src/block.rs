use core::fmt;
use std::ops::{Add, Deref, Sub};

use alloy_consensus::{Header, proofs::calculate_transaction_root};
use alloy_primitives::{Address, B64, B256, Bloom};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, Envelope, Indexed};
use serde::{Deserialize, Serialize};

use crate::Transaction;

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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Block(alloy_consensus::Block<Transaction>);

impl Block {
    pub fn new(parent: BlockHash, txs: Vec<Transaction>) -> Self {
        let body = alloy_consensus::BlockBody {
            transactions: txs.clone(),
            ommers: vec![],
            withdrawals: None,
        };
        let tx_root = calculate_transaction_root(&txs);
        let header = Header {
            parent_hash: *parent,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: tx_root,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            difficulty: B256::ZERO.into(),
            number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: vec![].into(),
            mix_hash: B256::ZERO,
            nonce: B64::default(),
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };
        Self(alloy_consensus::Block { header, body })
    }
}

impl std::ops::Deref for Block {
    type Target = alloy_consensus::Block<Transaction>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, Ord, PartialOrd, PartialEq, Eq)]
pub struct BlockHash(B256);

// TODO
impl Indexed for BlockHash {
    type Index = ();

    fn index(&self) -> Self::Index {}
}

impl From<[u8; 32]> for BlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }
}

impl std::ops::Deref for BlockHash {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockInfo<S: Clone> {
    num: BlockNumber,
    envelope: Envelope<BlockHash, S>,
}

impl<S: Clone> BlockInfo<S> {
    pub fn new(num: BlockNumber, signed: Envelope<BlockHash, S>) -> Self {
        Self {
            num,
            envelope: signed,
        }
    }

    pub fn number(&self) -> BlockNumber {
        self.num
    }

    pub fn envelope(&self) -> &Envelope<BlockHash, S> {
        &self.envelope
    }

    pub fn into_envelope(self) -> Envelope<BlockHash, S> {
        self.envelope
    }
}

pub struct CertifiedBlock {
    num: BlockNumber,
    cert: Certificate<BlockHash>,
    data: Block,
}

impl CertifiedBlock {
    pub fn new(num: BlockNumber, cert: Certificate<BlockHash>, data: Block) -> Self {
        Self { num, cert, data }
    }

    pub fn num(&self) -> BlockNumber {
        self.num
    }

    pub fn cert(&self) -> &Certificate<BlockHash> {
        &self.cert
    }

    pub fn data(&self) -> &Block {
        &self.data
    }
}
