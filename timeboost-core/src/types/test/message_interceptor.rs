use std::sync::Arc;

use sailfish_types::Message;

type NetworkMessageModifier<B> = Arc<dyn Fn(&Message<B>, u64) -> Result<Message<B>, String> + Send + Sync>;

/// Intercept a message before a node processes it and apply transformations if any provided
#[derive(Clone)]
pub struct NetworkMessageInterceptor<B> {
    msg_modifier: NetworkMessageModifier<B>,
}

impl<B> NetworkMessageInterceptor<B> {
    pub fn new<F>(msg_modifier: F) -> Self
    where
        F: Fn(&Message<B>, u64) -> Result<Message<B>, String> + Send + Sync + Clone + 'static,
    {
        Self {
            msg_modifier: Arc::new(msg_modifier),
        }
    }

    /// Handle the message with any defined logic in the test
    pub(crate) fn intercept_message(&self, msg: Message<B>, id: u64) -> Result<Message<B>, String> {
        (self.msg_modifier)(&msg, id)
    }
}

impl<B: Clone> Default for NetworkMessageInterceptor<B> {
    fn default() -> Self {
        Self {
            msg_modifier: Arc::new(|msg: &Message<B>, _id: u64| Ok(msg.clone())),
        }
    }
}

impl<B> std::fmt::Debug for NetworkMessageInterceptor<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NetworkMessageInterceptor",)
    }
}
