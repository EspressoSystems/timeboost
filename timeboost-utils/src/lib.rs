pub mod keyset;
pub mod load_generation;
pub mod types;
pub mod until;

use crate::keyset::PublicNodeInfo;

pub fn unsafe_zero_keypair<N: Into<u64>>(i: N) -> multisig::Keypair {
    sig_keypair_from_seed_indexed([0u8; 32], i.into())
}

pub fn sig_keypair_from_seed_indexed(seed: [u8; 32], index: u64) -> multisig::Keypair {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed);
    hasher.update(&index.to_le_bytes());
    let new_seed = *hasher.finalize().as_bytes();
    multisig::Keypair::from_seed(new_seed)
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
    keyset: &[PublicNodeInfo],
    nodes: usize,
    multi_region: bool,
) -> impl Iterator<Item = &PublicNodeInfo> {
    if multi_region {
        let take_from_group = nodes / 4;
        Box::new(
            keyset
                .chunks(4)
                .flat_map(move |v| v.iter().take(take_from_group)),
        )
    } else {
        Box::new(keyset.iter().take(nodes)) as Box<dyn Iterator<Item = _>>
    }
}
