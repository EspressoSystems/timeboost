use std::sync::Arc;

use crate::types::message::Message;

type NetworkMessageModifier = Arc<dyn Fn(&Message, u64) -> Result<Message, String> + Send + Sync>;
/// Intercept a message before a node processes it and apply transformations if any provided
#[derive(Clone)]
pub struct NetworkMessageInterceptor {
    msg_modifier: NetworkMessageModifier,
}

impl NetworkMessageInterceptor {
    pub fn new<F>(msg_modifier: F) -> Self
    where
        F: Fn(&Message, u64) -> Result<Message, String> + Send + Sync + Clone + 'static,
    {
        Self {
            msg_modifier: Arc::new(msg_modifier),
        }
    }

    /// Handle the message with any defined logic in the test
    pub(crate) fn intercept_message(&self, msg: Message, id: u64) -> Result<Message, String> {
        (self.msg_modifier)(&msg, id)
    }
}

impl Default for NetworkMessageInterceptor {
    fn default() -> Self {
        Self {
            msg_modifier: Arc::new(|msg: &Message, _id: u64| Ok(msg.clone())),
        }
    }
}

impl std::fmt::Debug for NetworkMessageInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetworkMessageInterceptor",)
    }
}
