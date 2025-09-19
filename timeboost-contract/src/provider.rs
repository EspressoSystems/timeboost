//! Helper functions to build Ethereum [providers](https://docs.rs/alloy/latest/alloy/providers/trait.Provider.html)
//! Partial Credit: <https://github.com/EspressoSystems/espresso-network/tree/main/contracts/rust/deployer>

use std::{ops::Deref, pin::Pin};

use alloy::{
    eips::BlockNumberOrTag,
    network::EthereumWallet,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, Log},
    signers::local::{LocalSignerError, MnemonicBuilder, PrivateKeySigner, coins_bip39::English},
    sol_types::SolEvent,
    transports::{http::reqwest::Url, ws::WsConnect},
};
use futures::{Stream, StreamExt};
use timeboost_types::{HttpProvider, HttpProviderWithWallet};
use tracing::error;

/// Build a local signer from wallet mnemonic and account index
pub fn build_signer(
    mnemonic: String,
    account_index: u32,
) -> Result<PrivateKeySigner, LocalSignerError> {
    MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .index(account_index)?
        .build()
}

/// a handy thin wrapper around wallet builder and provider builder that directly
/// returns an instantiated `Provider` with default fillers with wallet, ready to send tx
pub fn build_provider(
    mnemonic: String,
    account_index: u32,
    url: Url,
) -> Result<HttpProviderWithWallet, LocalSignerError> {
    let signer = build_signer(mnemonic, account_index)?;
    let wallet = EthereumWallet::from(signer);
    Ok(ProviderBuilder::new().wallet(wallet).connect_http(url))
}

/// A PubSub service (with backend handle), disconnect on drop.
#[derive(Clone)]
pub struct PubSubProvider(HttpProvider);

impl Deref for PubSubProvider {
    type Target = HttpProvider;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PubSubProvider {
    pub async fn new(ws_url: Url) -> anyhow::Result<Self> {
        let ws = WsConnect::new(ws_url);
        let provider = ProviderBuilder::new()
            .connect_pubsub_with(ws)
            .await
            .map_err(|err| {
                error!(?err, "event pubsub failed to start");
                err
            })?;
        Ok(Self(provider))
    }

    /// create an event stream of event type `E`, subscribing since `from_block` on `contract`
    pub async fn event_stream<E: SolEvent>(
        &self,
        contract: Address,
        from_block: BlockNumberOrTag,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = Log<E>>>>> {
        let filter = Filter::new()
            .address(contract)
            .event(E::SIGNATURE)
            .from_block(from_block);

        let events = self
            .subscribe_logs(&filter)
            .await
            .map_err(|err| {
                error!(?err, "pubsub subscription failed");
                err
            })?
            .into_stream();

        let validated = events.filter_map(|log| async move {
            match log.log_decode_validate::<E>() {
                Ok(event) => Some(event),
                Err(err) => {
                    error!(%err, "failed to parse `CommitteeCreated` event log");
                    None
                }
            }
        });

        Ok(Box::pin(validated))
    }
}
