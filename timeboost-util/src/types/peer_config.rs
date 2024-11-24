use std::{num::NonZeroUsize, time::Duration};

use bincode::Options;
use derivative::Derivative;
use displaydoc::Display;
use hotshot_types::traits::signature_key::SignatureKey;
use tide_disco::Url;
use tracing::error;

use crate::bincode_opts;

#[derive(serde::Serialize, serde::Deserialize, Clone, Derivative, Display)]
#[serde(bound(deserialize = ""))]
#[derivative(Debug(bound = ""))]
/// config for validator, including public key, private key, stake value
pub struct ValidatorConfig<KEY: SignatureKey> {
    /// The validator's public key and stake value
    pub public_key: KEY,
    /// The validator's private key, should be in the mempool, not public
    #[derivative(Debug = "ignore")]
    pub private_key: KEY::PrivateKey,
    /// The validator's stake
    pub stake_value: u64,
    /// Whether or not this validator is DA
    pub is_da: bool,
}

impl<KEY: SignatureKey> ValidatorConfig<KEY> {
    /// generate validator config from input seed, index, stake value, and whether it's DA
    #[must_use]
    pub fn generated_from_seed_indexed(
        seed: [u8; 32],
        index: u64,
        stake_value: u64,
        is_da: bool,
    ) -> Self {
        let (public_key, private_key) = KEY::generated_from_seed_indexed(seed, index);
        Self {
            public_key,
            private_key,
            stake_value,
            is_da,
        }
    }

    /// get the public config of the validator
    pub fn public_config(&self) -> PeerConfig<KEY> {
        PeerConfig {
            stake_table_entry: self.public_key.stake_table_entry(self.stake_value),
        }
    }
}

impl<KEY: SignatureKey> Default for ValidatorConfig<KEY> {
    fn default() -> Self {
        Self::generated_from_seed_indexed([0u8; 32], 0, 1, true)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Display, PartialEq, Eq, Hash)]
#[serde(bound(deserialize = ""))]
/// structure of peers' config, including public key, stake value, and state key.
pub struct PeerConfig<KEY: SignatureKey> {
    /// The peer's public key and stake value
    pub stake_table_entry: KEY::StakeTableEntry,
}

impl<KEY: SignatureKey> PeerConfig<KEY> {
    /// Serialize a peer's config to bytes
    pub fn to_bytes(config: &Self) -> Vec<u8> {
        let x = bincode_opts().serialize(config);
        match x {
            Ok(x) => x,
            Err(e) => {
                error!(?e, "Failed to serialize public key");
                vec![]
            }
        }
    }

    /// Deserialize a peer's config from bytes
    /// # Errors
    /// Will return `None` if deserialization fails
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let x: Result<PeerConfig<KEY>, _> = bincode_opts().deserialize(bytes);
        match x {
            Ok(pub_key) => Some(pub_key),
            Err(e) => {
                error!(?e, "Failed to deserialize public key");
                None
            }
        }
    }
}

impl<KEY: SignatureKey> Default for PeerConfig<KEY> {
    fn default() -> Self {
        let default_validator_config = ValidatorConfig::<KEY>::default();
        default_validator_config.public_config()
    }
}

/// Holds configuration for a `HotShot`
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = ""))]
pub struct HotShotConfig<KEY: SignatureKey> {
    /// The proportion of nodes required before the orchestrator issues the ready signal,
    /// expressed as (numerator, denominator)
    pub start_threshold: (u64, u64),
    /// Total number of nodes in the network
    // Earlier it was total_nodes
    pub num_nodes_with_stake: NonZeroUsize,
    /// List of known node's public keys and stake value for certificate aggregation, serving as public parameter
    pub known_nodes_with_stake: Vec<PeerConfig<KEY>>,
    /// All public keys known to be DA nodes
    pub known_da_nodes: Vec<PeerConfig<KEY>>,
    /// List of known non-staking nodes' public keys
    pub known_nodes_without_stake: Vec<KEY>,
    /// My own validator config, including my public key, private key, stake value, serving as private parameter
    pub my_own_validator_config: ValidatorConfig<KEY>,
    /// List of DA committee (staking)nodes for static DA committee
    pub da_staked_committee_size: usize,
    /// Number of fixed leaders for GPU VID, normally it will be 0, it's only used when running GPU VID
    pub fixed_leader_for_gpuvid: usize,
    /// Base duration for next-view timeout, in milliseconds
    pub next_view_timeout: u64,
    /// Duration of view sync round timeouts
    pub view_sync_timeout: Duration,
    /// The exponential backoff ration for the next-view timeout
    pub timeout_ratio: (u64, u64),
    /// The delay a leader inserts before starting pre-commit, in milliseconds
    pub round_start_delay: u64,
    /// Delay after init before starting consensus, in milliseconds
    pub start_delay: u64,
    /// Number of network bootstrap nodes
    pub num_bootstrap: usize,
    /// The maximum amount of time a leader can wait to get a block from a builder
    pub builder_timeout: Duration,
    /// time to wait until we request data associated with a proposal
    pub data_request_delay: Duration,
    /// Builder API base URL
    pub builder_urls: Vec<Url>,
    /// View to start proposing an upgrade
    pub start_proposing_view: u64,
    /// View to stop proposing an upgrade. To prevent proposing an upgrade, set stop_proposing_view <= start_proposing_view.
    pub stop_proposing_view: u64,
    /// View to start voting on an upgrade
    pub start_voting_view: u64,
    /// View to stop voting on an upgrade. To prevent voting on an upgrade, set stop_voting_view <= start_voting_view.
    pub stop_voting_view: u64,
    /// Unix time in seconds at which we start proposing an upgrade
    pub start_proposing_time: u64,
    /// Unix time in seconds at which we stop proposing an upgrade. To prevent proposing an upgrade, set stop_proposing_time <= start_proposing_time.
    pub stop_proposing_time: u64,
    /// Unix time in seconds at which we start voting on an upgrade
    pub start_voting_time: u64,
    /// Unix time in seconds at which we stop voting on an upgrade. To prevent voting on an upgrade, set stop_voting_time <= start_voting_time.
    pub stop_voting_time: u64,
    /// Number of blocks in an epoch, zero means there are no epochs
    pub epoch_height: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = ""))]
/// Holds configuration for the upgrade task.
pub struct UpgradeConfig {
    /// View to start proposing an upgrade
    pub start_proposing_view: u64,
    /// View to stop proposing an upgrade. To prevent proposing an upgrade, set stop_proposing_view <= start_proposing_view.
    pub stop_proposing_view: u64,
    /// View to start voting on an upgrade
    pub start_voting_view: u64,
    /// View to stop voting on an upgrade. To prevent voting on an upgrade, set stop_voting_view <= start_voting_view.
    pub stop_voting_view: u64,
    /// Unix time in seconds at which we start proposing an upgrade
    pub start_proposing_time: u64,
    /// Unix time in seconds at which we stop proposing an upgrade. To prevent proposing an upgrade, set stop_proposing_time <= start_proposing_time.
    pub stop_proposing_time: u64,
    /// Unix time in seconds at which we start voting on an upgrade
    pub start_voting_time: u64,
    /// Unix time in seconds at which we stop voting on an upgrade. To prevent voting on an upgrade, set stop_voting_time <= start_voting_time.
    pub stop_voting_time: u64,
}

// Explicitly implementing `Default` for clarity.
#[allow(clippy::derivable_impls)]
impl Default for UpgradeConfig {
    fn default() -> Self {
        UpgradeConfig {
            start_proposing_view: u64::MAX,
            stop_proposing_view: 0,
            start_voting_view: u64::MAX,
            stop_voting_view: 0,
            start_proposing_time: u64::MAX,
            stop_proposing_time: 0,
            start_voting_time: u64::MAX,
            stop_voting_time: 0,
        }
    }
}
