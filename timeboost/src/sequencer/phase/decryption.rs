use anyhow::Result;

use super::inclusion::InclusionList;

pub mod canonical;
pub mod noop;

/// The decryption phase takes the consensus inclusion list produced by the inclusion phase,
/// and threshold-decrypts any encrypted transactions or bundles in the list.
/// https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main?plain=1#L128
pub trait DecryptionPhase {
    fn decrypt(
        &mut self,
        inclusion_list: InclusionList,
    ) -> impl std::future::Future<Output = Result<InclusionList>> + Send;
}
