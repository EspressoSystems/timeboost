use std::collections::BTreeSet;

use crate::{PriorityBundle, Transaction};

#[derive(Debug, Default)]
pub struct RetryList {
    transactions: BTreeSet<Transaction>,
    bundles: BTreeSet<PriorityBundle>,
}

impl RetryList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_transaction(&mut self, t: Transaction) {
        self.transactions.insert(t);
    }

    pub fn add_bundle(&mut self, b: PriorityBundle) {
        self.bundles.insert(b);
    }

    pub fn into_parts(self) -> (BTreeSet<Transaction>, BTreeSet<PriorityBundle>) {
        (self.transactions, self.bundles)
    }
}
