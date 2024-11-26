use std::num::NonZeroUsize;
use std::sync::Arc;

use crossbeam_queue::ArrayQueue;
use tokio::sync::Notify;

#[derive(Debug)]
pub struct Producer<T>(Arc<Ringbuf<T>>);

impl<T> Producer<T> {
    pub fn push(&mut self, x: T) {
        self.0.buf.force_push(x);
        self.0.sig.notify_waiters()
    }
}

#[derive(Debug)]
pub struct Consumer<T>(Arc<Ringbuf<T>>);

impl<T> Consumer<T> {
    pub async fn next(&mut self) -> T {
        let future = self.0.sig.notified();
        if let Some(x) = self.0.buf.pop() {
            return x
        }
        future.await;
        self.0.buf.pop().expect("item available after notification")
    }

    pub fn pop(&mut self) -> Option<T> {
        self.0.buf.pop()
    }

    pub fn len(&self) -> usize {
        self.0.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.buf.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.0.buf.is_full()
    }
}

#[derive(Debug)]
struct Ringbuf<T> {
    buf: ArrayQueue<T>,
    sig: Notify
}

pub fn ringbuf<T>(cap: NonZeroUsize) -> (Producer<T>, Consumer<T>) {
    let r = Arc::new(Ringbuf {
        buf: ArrayQueue::new(cap.get()),
        sig: Notify::new()
    });
    let p = Producer(r.clone());
    let c = Consumer(r);
    (p, c)
}

