pub mod keyset;
pub mod load_generation;
pub mod types;
pub mod until;

use crate::keyset::NodeInfo;
use multisig::x25519;

pub fn unsafe_zero_keypair<N: Into<u64>>(i: N) -> multisig::Keypair {
    sig_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn unsafe_zero_dh_keypair<N: Into<u64>>(i: N) -> x25519::Keypair {
    dh_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn sig_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> multisig::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    multisig::Keypair::from_seed(new_seed)
}

pub fn dh_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> x25519::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    x25519::Keypair::from_seed(new_seed).unwrap()
}

pub fn bs58_encode(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

/// Selects peer hosts from a keyset according to region logic.
/// The selection is based on the offset of the file. The file is
/// arranged with 20 keys, and each group of 4 is associated with
/// a region. If `multi_region` is true, the selection will be
/// based on the region, where it'll offset. So if we have 5 nodes
/// then the indexing scheme would be 0 5 10 15 for the region.
///
/// - `keyset` is the slice of PublicNodeInfo (from KeysetConfig)
/// - `nodes` is the number of nodes to select
/// - `multi_region` determines whether to use region chunking logic
///
/// Returns a boxed iterator over the selected PublicNodeInfo references.
pub fn select_peer_hosts(
    keyset: &[NodeInfo],
    multi_region: bool,
) -> impl Iterator<Item = &NodeInfo> {
    if multi_region {
        let take_from_group = keyset.len() / 4;
        Box::new(
            keyset
                .chunks(4)
                .flat_map(move |v| v.iter().take(take_from_group)),
        )
    } else {
        Box::new(keyset.iter().take(keyset.len())) as Box<dyn Iterator<Item = _>>
    }
}

/// Wrapper iterator that bridges type conversion
/// from Iterator<Item = Result<T, E>> to Iterator<Item = T>
/// while early-returning an Err(E) if any item is an Err, without collecting or allocating memory.
///
/// # Usage
/// ```no_run
/// fn use_result_iter<I, T, E>(iter: I) -> Result<(), E>
/// where
///     I: Iterator<Item = Result<T, E>>,
/// {
///     let mut result_iter = ResultIter::new(iter);
///     for _ in &mut result_iter {
///         // use item
///     }
///     result_iter.result()
/// }
/// ```
pub struct ResultIter<I, T, E>
where
    I: Iterator<Item = Result<T, E>>,
{
    iter: I,
    error: Option<E>,
}

impl<I, T, E> ResultIter<I, T, E>
where
    I: Iterator<Item = Result<T, E>>,
{
    /// construct a new ResultIter
    pub fn new(iter: I) -> Self {
        Self { iter, error: None }
    }

    /// Get the early-return result
    pub fn result(self) -> Result<(), E> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<I, T, E> Iterator for ResultIter<I, T, E>
where
    I: Iterator<Item = Result<T, E>>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() {
            return None;
        }
        match self.iter.next() {
            Some(Ok(v)) => Some(v),
            Some(Err(e)) => {
                self.error = Some(e);
                None
            }
            None => None,
        }
    }
}
