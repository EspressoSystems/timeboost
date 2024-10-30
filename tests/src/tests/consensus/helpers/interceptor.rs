use std::collections::VecDeque;

use sailfish::consensus::Consensus;
use timeboost_core::types::{message::Message, round_number::RoundNumber};

use super::test_helpers::MessageModifier;
/// Intercept a message before a node processes it and apply transformations if any provided
pub struct Interceptor {
    msg_modifier: MessageModifier,
    modify_at_round: RoundNumber,
}

impl Interceptor {
    pub(crate) fn new<F>(msg_modifier: F, modify_at_round: RoundNumber) -> Self
    where
        F: Fn(&Message, &mut Consensus, &mut VecDeque<Message>) -> Vec<Message> + 'static,
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
        node: &mut Consensus,
        queue: &mut VecDeque<Message>,
    ) -> Vec<Message> {
        let round = msg.round();
        if self.modify_at_round == round {
            let new_msg = (self.msg_modifier)(&msg, node, queue);
            return new_msg;
        }

        vec![msg]
    }
}

impl Default for Interceptor {
    fn default() -> Self {
        Self {
            modify_at_round: RoundNumber::new(0),
            msg_modifier: Box::new(
                |msg: &Message, _node: &mut Consensus, _queue: &mut VecDeque<Message>| {
                    vec![msg.clone()]
                },
            ),
        }
    }
}
