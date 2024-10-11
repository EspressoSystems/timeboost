use hotshot::types::BLSPubKey;
use hotshot_types::{traits::states::InstanceState, ValidatorConfig};

/// Represents the immutable state of the sailfish node.
#[derive(Debug, Clone)]
pub struct SailfishState {
    /// The ID of the sailfish node.
    pub id: u64,

    /// The validator config of the sailfish node.
    pub validator_config: ValidatorConfig<BLSPubKey>,
}

impl InstanceState for SailfishState {}
