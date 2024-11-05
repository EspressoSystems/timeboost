use crate::types::seqno::SeqNo;
use crate::types::time::Epoch;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce {
    epoch: Epoch,
    seqno: SeqNo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction<A, D> {
    to: A,
    nonce: Nonce,
    data: D,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transactions<A, D> {
    Priority {
        to: A,
        nonce: Nonce,
        txns: BTreeSet<Transaction<A, D>>,
    },
    Regular {
        txn: Transaction<A, D>,
    },
}
