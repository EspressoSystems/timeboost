use timeboost_types::{InclusionList, Transaction};

#[derive(Debug)]
pub struct Sorter {}

impl Sorter {
    pub fn new() -> Self {
        Self {}
    }

    pub fn sort(&mut self, list: InclusionList) -> impl Iterator<Item = Transaction> {
        // TODO
        let (_, t) = list.into_transactions();
        t.into_iter()
    }
}
