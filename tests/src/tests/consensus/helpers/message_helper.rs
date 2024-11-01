use std::collections::HashMap;

use timeboost_core::types::{
    envelope::Envelope, message::Message, vertex::VertexId, PrivateKey, PublicKey,
};

use super::{node_instrument::TestNodeInstrument, test_helpers::create_vertex};

struct KeyMapping {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl KeyMapping {
    fn new(private_key: PrivateKey, public_key: PublicKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

pub struct MessageHelper {
    keys: HashMap<u64, KeyMapping>,
}

impl MessageHelper {
    pub(crate) fn new(keys: &[(PrivateKey, PublicKey)]) -> Self {
        Self {
            keys: keys
                .iter()
                .enumerate()
                .map(|(id, (private_key, public_key))| {
                    (id as u64, KeyMapping::new(private_key.clone(), *public_key))
                })
                .collect(),
        }
    }

    pub(crate) fn create_vertex_msgs(&self, round: u64, edges: Vec<VertexId>) -> Vec<Message> {
        self.keys
            .keys()
            .map(|id| self.create_vertex_msgs_for_node_id(id, round, edges.clone()))
            .collect()
    }

    pub(crate) fn create_vertex_msgs_for_node_id(
        &self,
        id: &u64,
        round: u64,
        edges: Vec<VertexId>,
    ) -> Message {
        let keys = self.keys.get(id).unwrap();
        let mut v = create_vertex(round, keys.public_key);
        v.add_strong_edges(edges);
        let e = Envelope::signed(v, keys.private_key(), keys.public_key());
        Message::Vertex(e.cast())
    }

    pub(crate) fn add_vertices_to_node(
        &self,
        round: u64,
        node_handle: &mut TestNodeInstrument,
    ) -> Vec<VertexId> {
        self.keys
            .values()
            .map(|keys| {
                let v = create_vertex(round, keys.public_key);
                node_handle.add_vertex_to_dag(v.clone());
                *v.id()
            })
            .collect()
    }
}
