use timeboost_core::types::{
    committee::StaticCommittee, message::Message, round_number::RoundNumber,
};

use super::test_helpers::MessageModifier;
/// Intercept a message before a node processes it and apply transformations if any provided
pub struct Interceptor {
    msg_modifier: MessageModifier,
    modify_at_round: RoundNumber,
}

impl Interceptor {
    pub(crate) fn new(msg_modifier: MessageModifier, modify_at_round: RoundNumber) -> Self {
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
            modify_at_round: RoundNumber::genesis(),
            msg_modifier: Box::new(|msg: &Message, _committee: &StaticCommittee| vec![msg.clone()]),
        }
    }
}
