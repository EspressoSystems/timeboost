use std::cmp::Ordering;
use std::ops::Deref;

use timeboost_core::types::vertex::Vertex;

/// Newtype for `Vertex` that implements `Ord` by round number.
#[derive(Debug)]
pub struct OrderedVertex(pub Vertex);

impl From<Vertex> for OrderedVertex {
    fn from(value: Vertex) -> Self {
        Self(value)
    }
}

impl From<OrderedVertex> for Vertex {
    fn from(value: OrderedVertex) -> Self {
        value.0
    }
}

impl Deref for OrderedVertex {
    type Target = Vertex;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for OrderedVertex {
    fn eq(&self, other: &Self) -> bool {
        self.round() == other.round() && self.source() == other.source()
    }
}

impl Eq for OrderedVertex {}

impl Ord for OrderedVertex {
    fn cmp(&self, other: &Self) -> Ordering {
        self.round()
            .cmp(&other.round())
            .then_with(|| self.source().cmp(other.source()))
    }
}

impl PartialOrd for OrderedVertex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
