use bon::Builder;
use cliquenet::Address;

#[derive(Debug, Clone, Builder)]
pub(crate) struct YapperConfig {
    /// RPC API addresses to receive bundles
    pub(crate) addresses: Vec<Address>,
    /// Transactions per second to send
    pub(crate) tps: u32,
    /// Are we setup with nitro?
    pub(crate) nitro_integration: bool,
    /// URL of nitro chain that is configured
    pub(crate) nitro_url: String,
    /// Limit on the number of transactions we want to send
    pub(crate) txn_limit: u64,
    /// Chain id for l2 chain
    pub(crate) chain_id: u64,
}
