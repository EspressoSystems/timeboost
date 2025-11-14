use bon::Builder;
use cliquenet::Address;
use reqwest::Url;

#[derive(Debug, Clone, Builder)]
pub(crate) struct YapperConfig {
    /// RPC API addresses to receive bundles
    pub(crate) addresses: Vec<Address>,
    /// Transactions per second to send
    pub(crate) tps: u32,
    /// Ratio of encrypted bundles
    pub(crate) enc_ratio: f64,
    /// Ratio of priority bundles
    pub(crate) prio_ratio: f64,

    // Nitro-specific configs
    /// URL of nitro chain that is configured
    pub(crate) nitro_url: Option<Url>,
    /// Number of sender addresses on Nitro L2
    pub(crate) nitro_senders: u32,
    /// Chain id for l2 chain
    pub(crate) chain_id: u64,
    /// Chain id id for the parent chain
    pub(crate) parent_id: u64,
    /// URL of the parent chain that is configured
    pub(crate) parent_url: Url,
    /// Bridge address
    pub(crate) bridge_addr: alloy::primitives::Address,
}
