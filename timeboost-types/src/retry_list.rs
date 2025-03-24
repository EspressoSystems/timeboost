use crate::{Bundle, PriorityBundle, bundle::Signed};
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct RetryList {
    regular: HashSet<Bundle>,
    priority: HashSet<PriorityBundle<Signed>>,
}

impl RetryList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_regular(&mut self, r: Bundle) {
        self.regular.insert(r);
    }

    pub fn add_priority(&mut self, b: PriorityBundle<Signed>) {
        self.priority.insert(b);
    }

    pub fn into_parts(self) -> (HashSet<PriorityBundle<Signed>>, HashSet<Bundle>) {
        (self.priority, self.regular)
    }
}
