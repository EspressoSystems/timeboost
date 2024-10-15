use anyhow::Result;
use hotshot::types::{BLSPrivKey, BLSPubKey};
use hotshot_types::data::ViewNumber;

use crate::types::message::SailfishEvent;

/// The context of a task, including its public and private keys. The context is passed
/// immutably to the task function.
#[derive(Clone, Debug)]
pub struct TaskContext {
    /// The public key of the node running this task.
    pub public_key: BLSPubKey,

    /// The private key of the node running this task.
    pub private_key: BLSPrivKey,

    /// The ID of the node running this task.
    pub id: u64,

    /// The view number of the node running this task.
    pub view_number: ViewNumber,
}

/// The core consensus state.
pub struct Consensus {
    /// The current round number.
    _round_number: ViewNumber,
}

impl Consensus {
    pub fn handle_event(&mut self, event: SailfishEvent) -> Result<Vec<SailfishEvent>> {
        match event {
            SailfishEvent::Shutdown => todo!(),
            SailfishEvent::DummySend(_) => todo!(),
            SailfishEvent::DummyRecv(_) => todo!(),
            SailfishEvent::VertexSend(_vertex) => todo!(),
            SailfishEvent::TimeoutSend(_timeout) => todo!(),
            SailfishEvent::NoVoteSend(_no_vote) => todo!(),
            SailfishEvent::VertexRecv(_vertex) => todo!(),
            SailfishEvent::TimeoutRecv(_timeout) => todo!(),
            SailfishEvent::NoVoteRecv(_no_vote) => todo!(),
        }
    }
}
