use std::sync::Arc;

use committable::Committable;
use sailfish_types::Message;

type NetworkMessageModifier<T> =
    Arc<dyn Fn(&Message<T>, u64) -> Result<Message<T>, String> + Send + Sync>;

/// Intercept a message before a node processes it and apply transformations if any provided
#[derive(Clone)]
pub struct NetworkMessageInterceptor<T: Committable> {
    msg_modifier: NetworkMessageModifier<T>,
}

impl<T: Committable> NetworkMessageInterceptor<T> {
    pub fn new<F>(msg_modifier: F) -> Self
    where
        F: Fn(&Message<T>, u64) -> Result<Message<T>, String> + Send + Sync + Clone + 'static,
    {
        Self {
            msg_modifier: Arc::new(msg_modifier),
        }
    }

    /// Handle the message with any defined logic in the test
    pub(crate) fn intercept_message(&self, msg: Message<T>, id: u64) -> Result<Message<T>, String> {
        (self.msg_modifier)(&msg, id)
    }
}

impl<T: Committable + Clone> Default for NetworkMessageInterceptor<T> {
    fn default() -> Self {
        Self {
            msg_modifier: Arc::new(|msg: &Message<T>, _id: u64| Ok(msg.clone())),
        }
    }
}

impl<T: Committable> std::fmt::Debug for NetworkMessageInterceptor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetworkMessageInterceptor",)
    }
}
