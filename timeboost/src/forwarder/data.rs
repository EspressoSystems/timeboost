use std::num::TryFromIntError;

use alloy_eips::Encodable2718;
use prost::Message;
use sailfish::types::RoundNumber;
use timeboost_proto::inclusion as proto;
use timeboost_types::{Timestamp, Transaction};

pub struct Data(u32, Vec<u8>);

impl Data {
    pub fn len(&self) -> u32 {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn bytes(&self) -> &[u8] {
        &self.1
    }

    pub fn encode<'a, R, T, I>(r: R, t: T, txs: I) -> Result<Self, DataError>
    where
        R: Into<RoundNumber>,
        T: Into<Timestamp>,
        I: IntoIterator<Item = &'a Transaction>,
    {
        let round = r.into();
        let inclusion = proto::InclusionList {
            round: *round,
            encoded_txns: txs
                .into_iter()
                .map(|tx| proto::Transaction {
                    encoded_txn: tx.encoded_2718(),
                    address: tx.address().as_slice().to_vec(),
                    timestamp: **tx.time(),
                })
                .collect(),
            consensus_timestamp: *t.into(),
            delayed_messages_read: 0,
        };

        let bytes = inclusion.encode_to_vec();
        let len: u32 = bytes.len().try_into()?;

        Ok(Self(len, bytes))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("inclusion list size exceeds allowed maximum")]
    Size(#[from] TryFromIntError),

    #[error("bincode serialization error: {0}")]
    Bincode(#[from] bincode::error::EncodeError),
}
