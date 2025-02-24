use std::collections::HashMap;

use multisig::PublicKey;

use super::{key_manager::KeyManager, node_instrument::TestNodeInstrument};
use crate::prelude::*;

pub(crate) type MessageModifier = Box<dyn Fn(&Message, &mut TestNodeInstrument) -> Vec<Message>>;

pub(crate) fn make_consensus_nodes(
    num_nodes: u8,
) -> (HashMap<PublicKey, TestNodeInstrument>, KeyManager) {
    let manager = KeyManager::new(num_nodes);
    let nodes = manager.create_node_instruments();
    let nodes = nodes
        .into_iter()
        .map(|node_instrument| (node_instrument.node().public_key(), node_instrument))
        .collect();
    (nodes, manager)
}
