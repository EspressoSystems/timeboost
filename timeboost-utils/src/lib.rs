use std::{future::Future, pin::Pin};

pub mod traits;
pub mod types;

/// Pinned future that is Send and Sync
pub type BoxSyncFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;

/// yoinked from futures crate
pub fn assert_future<T, F>(future: F) -> F
where
    F: Future<Output = T>,
{
    future
}
/// yoinked from futures crate, adds sync bound that we need
pub fn boxed_sync<'a, F>(fut: F) -> BoxSyncFuture<'a, F::Output>
where
    F: Future + Sized + Send + Sync + 'a,
{
    assert_future::<F::Output, _>(Box::pin(fut))
}

pub fn unsafe_zero_keypair<N: Into<u64>>(i: N) -> multisig::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0u8; 32]);
    hasher.update(&i.into().to_le_bytes());
    let seed = *hasher.finalize().as_bytes();
    multisig::Keypair::from_seed(seed)
}
