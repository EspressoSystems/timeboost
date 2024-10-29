use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use sailfish::{consensus::committee::StaticCommittee, types::message::Message};

use super::test_helpers::MessageModifier;
/// Intercept a message before a node processes it and apply transformations if any provided
pub struct Interceptor {
    msg_modifier: MessageModifier,
    modify_at_round: ViewNumber,
}

impl Interceptor {
    pub(crate) fn new(msg_modifier: MessageModifier, modify_at_round: ViewNumber) -> Self {
        Self {
            msg_modifier,
            modify_at_round,
        }
    }

    /// Handle the message with any defined logic in the test
    pub(crate) fn intercept_message(
        &self,
        msg: Message,
        committe: &StaticCommittee,
    ) -> Vec<Message> {
        let round = msg.round();
        if self.modify_at_round == round {
            let new_msg = (self.msg_modifier)(&msg, committe);
            return new_msg;
        }

        vec![msg]
    }
}

impl Default for Interceptor {
    fn default() -> Self {
        Self {
            modify_at_round: ViewNumber::new(0),
            msg_modifier: Box::new(|msg: &Message, _committee: &StaticCommittee| vec![msg.clone()]),
        }
    }
}
