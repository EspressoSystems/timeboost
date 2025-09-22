use bon::Builder;
use cliquenet::Address;
use reqwest::Url;
use timeboost::crypto::prelude::ThresholdEncKey;

#[derive(Debug, Clone, Builder)]
pub(crate) struct YapperConfig {
    /// RPC API addresses to receive bundles
    pub(crate) addresses: Vec<Address>,
    /// Transactions per second to send
    pub(crate) tps: u32,
    /// URL of nitro chain that is configured
    pub(crate) nitro_url: Option<Url>,
    /// Chain id for l2 chain
    pub(crate) chain_id: u64,
    /// Use a given threshold encryption key, instead of fetching from nodes
    pub(crate) threshold_enc_key: Option<ThresholdEncKey>,
}
