use std::collections::VecDeque;
use std::future::{pending, Pending};

use timeboost_types::InclusionList;

#[derive(Debug)]
pub struct Decrypter {
    queue: VecDeque<InclusionList>,
    forever: Pending<InclusionList>,
}

impl Decrypter {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            forever: pending(),
        }
    }

    pub fn enqueue<I>(&mut self, incl: I)
    where
        I: IntoIterator<Item = InclusionList>,
    {
        self.queue.extend(incl);
    }

    pub async fn next(&mut self) -> Result<InclusionList, DecryptError> {
        if let Some(i) = self.queue.pop_front() {
            return Ok(i);
        }
        Ok(self.forever.clone().await)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecryptError {}
