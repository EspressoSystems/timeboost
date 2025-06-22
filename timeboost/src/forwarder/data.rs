use alloy_eips::Encodable2718;
use prost::Message;
use sailfish::types::RoundNumber;
use timeboost_proto::proto_types::InclusionList;
use timeboost_types::{Timestamp, Transaction};

pub struct Data(u64, Vec<u8>);

impl Data {
    pub fn len(&self) -> u64 {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn bytes(&self) -> &[u8] {
        &self.1
    }

    pub fn encode<'a, R, T, I>(r: R, t: T, txs: I) -> Self
    where
        R: Into<RoundNumber>,
        T: Into<Timestamp>,
        I: IntoIterator<Item = &'a Transaction>,
    {
        let round = r.into();
        let inclusion = InclusionList {
            round: *round,
            encoded_txns: txs
                .into_iter()
                .map(|tx| timeboost_proto::proto_types::Transaction {
                    encoded_txn: tx.encoded_2718(),
                    address: tx.address().as_slice().to_vec(),
                    timestamp: **tx.time(),
                })
                .collect(),
            consensus_timestamp: *t.into(),
            delayed_messages_read: 0,
        };

        let bytes = inclusion.encode_to_vec();
        let len: u64 = bytes.len() as u64;

        Self(len, bytes)
    }
}
