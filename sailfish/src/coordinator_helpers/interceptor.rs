use std::sync::Arc;

use timeboost_core::types::{committee::StaticCommittee, message::Message};

pub type NetworkMessageModifier =
    Arc<dyn Fn(&Message, &StaticCommittee) -> Vec<Message> + Send + Sync>;
/// Intercept a message before a node processes it and apply transformations if any provided
#[derive(Clone)]
pub struct NetworkMessageInterceptor {
    msg_modifier: NetworkMessageModifier,
}

impl NetworkMessageInterceptor {
    pub fn new<F>(msg_modifier: F) -> Self
    where
        F: Fn(&Message, &StaticCommittee) -> Vec<Message> + Send + Sync + Clone + 'static,
    {
        Self {
            msg_modifier: Arc::new(msg_modifier),
        }
    }

    /// Handle the message with any defined logic in the test
    pub(crate) fn intercept_message(
        &self,
        msg: Message,
        committee: &StaticCommittee,
    ) -> Vec<Message> {
        (self.msg_modifier)(&msg, committee)
    }
}

impl Default for NetworkMessageInterceptor {
    fn default() -> Self {
        Self {
            msg_modifier: Arc::new(|msg: &Message, _committee: &StaticCommittee| vec![msg.clone()]),
        }
    }
}
