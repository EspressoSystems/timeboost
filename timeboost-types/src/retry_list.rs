use crate::{PriorityBundle, Transaction};
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct RetryList {
    transactions: HashSet<Transaction>,
    bundles: HashSet<PriorityBundle>,
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

    pub fn priority_bundles(&self) -> &HashSet<PriorityBundle> {
        &self.bundles
    }

    pub fn transactions(&self) -> &HashSet<Transaction> {
        &self.transactions
    }

    pub fn into_parts(self) -> (HashSet<Transaction>, HashSet<PriorityBundle>) {
        (self.transactions, self.bundles)
    }
}
