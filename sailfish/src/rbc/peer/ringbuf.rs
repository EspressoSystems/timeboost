use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::Notify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u64);

#[derive(Debug)]
pub struct Producer<T>(Arc<Ringbuf<T>>);

impl<T> Producer<T> {
    pub fn push(&mut self, x: T) {
        let mut xs = self.0.buf.write();
        if xs.buf.len() == self.0.cap {
            xs.buf.pop_front();
        }
        let Version(v) = xs.ctr;
        xs.buf.push_back((Version(v + 1), x));
        xs.ctr = Version(v + 1);
        self.0.sig.notify_waiters()
    }
}

#[derive(Debug, Clone)]
pub struct Consumer<T>(Arc<Ringbuf<T>>);

impl<T> Consumer<T> {
    pub async fn pop(&self) -> (Version, T) {
        let future = self.0.sig.notified();
        {
            if let Some(val) = self.0.buf.write().buf.pop_front() {
                return val;
            }
        }
        future.await;
        self.0
            .buf
            .write()
            .buf
            .pop_front()
            .expect("item available after notification")
    }

    pub fn drop_head_if(&self, v1: Version) {
        let mut xs = self.0.buf.write();
        if xs.buf.front().map(|(v2, _)| v1 == *v2).unwrap_or(false) {
            xs.buf.pop_front();
        }
    }

    pub fn head_version(&self) -> Option<Version> {
        self.0.buf.read().buf.front().map(|(v, _)| *v)
    }
}

impl<T: Clone> Consumer<T> {
    pub async fn peek(&self) -> (Version, T) {
        let future = self.0.sig.notified();
        {
            if let Some(val) = self.0.buf.read().buf.front().cloned() {
                return val;
            }
        }
        future.await;
        self.0
            .buf
            .read()
            .buf
            .front()
            .cloned()
            .expect("item available after notification")
    }
}

#[derive(Debug)]
struct Ringbuf<T> {
    cap: usize,
    buf: RwLock<Buf<T>>,
    sig: Notify,
}

#[derive(Debug)]
struct Buf<T> {
    ctr: Version,
    buf: VecDeque<(Version, T)>,
}

pub fn ringbuf<T>(cap: NonZeroUsize) -> (Producer<T>, Consumer<T>) {
    let r = Arc::new(Ringbuf {
        cap: cap.get(),
        buf: RwLock::new(Buf {
            ctr: Version(0),
            buf: VecDeque::with_capacity(cap.get()),
        }),
        sig: Notify::new(),
    });
    let p = Producer(r.clone());
    let c = Consumer(r);
    (p, c)
}
