use std::{future::pending, time::Duration};

use multisig::PublicKey;
use tokio::{task::JoinSet, time::sleep};
use tracing::debug;

/// A set of timer tasks, delivering a value after some duration.
#[derive(Debug)]
pub struct Timer<T> {
    label: PublicKey,
    pending: JoinSet<T>,
}

impl<T: Send + 'static> Timer<T> {
    pub fn new(label: PublicKey) -> Self {
        let mut p = JoinSet::new();
        p.spawn(pending());
        Self { label, pending: p }
    }

    pub fn set(&mut self, v: T, d: Duration) {
        debug!(node = %self.label, timers = %self.pending.len());
        self.pending.spawn(async move {
            sleep(d).await;
            v
        });
    }

    pub fn try_next(&mut self) -> Option<T> {
        self.pending.try_join_next()?.ok()
    }

    pub async fn next(&mut self) -> T {
        self.pending
            .join_next()
            .await
            .expect("pending is never empty")
            .expect("sleep does not panic")
    }
}
