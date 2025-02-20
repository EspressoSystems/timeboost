use sailfish::types::RoundNumber;

use super::{node_instrument::TestNodeInstrument, test_helpers::MessageModifier};
use crate::prelude::*;

/// Intercept a message before a node processes it and apply transformations if any provided
pub struct Interceptor {
    msg_modifier: MessageModifier,
    modify_at_round: RoundNumber,
}

impl Interceptor {
    pub(crate) fn new<F>(msg_modifier: F, modify_at_round: RoundNumber) -> Self
    where
        F: Fn(&Message, &mut TestNodeInstrument) -> Vec<Message> + 'static,
    {
        Self {
            msg_modifier: Box::new(msg_modifier),
            modify_at_round,
        }
    }

    /// Handle the message with any defined logic in the test
    pub(crate) fn intercept_message(
        &self,
        msg: Message,
        node_handle: &mut TestNodeInstrument,
    ) -> Vec<Message> {
        let round = msg.round();
        if self.modify_at_round == round {
            let new_msg = (self.msg_modifier)(&msg, node_handle);
            return new_msg;
        }

        vec![msg]
    }
}

impl Default for Interceptor {
    fn default() -> Self {
        Self {
            modify_at_round: RoundNumber::new(0),
            msg_modifier: Box::new(|msg: &Message, _node: &mut TestNodeInstrument| {
                vec![msg.clone()]
            }),
        }
    }
}
