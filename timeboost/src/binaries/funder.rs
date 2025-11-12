use std::str::FromStr;

use alloy::{
    consensus::{SignableTransaction, TxEnvelope, TxLegacy},
    network::{Ethereum, TxSignerSync},
    primitives::{Address, U256},
    providers::{Provider, RootProvider},
    rlp::{BytesMut, Encodable},
    signers::local::PrivateKeySigner,
};
use anyhow::Result;
use clap::Parser;
use multisig::CommitteeId;
use timeboost::committee::CommitteeInfo;
use timeboost_utils::types::logging;
use tracing::info;
use url::Url;

#[derive(Parser, Debug)]
struct Cli {
    /// Path to node configuration.
    #[clap(long, short)]
    parent_rpc_url: Url,

    #[clap(long, default_value = "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35")]
    key_manager_contract: Address,

    #[clap(
        long,
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    funder_private_key: String,

    #[clap(long, default_value_t = 0)]
    committee_id: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();
    let comm_info = CommitteeInfo::fetch(
        cli.parent_rpc_url.clone(),
        cli.key_manager_contract,
        CommitteeId::from(cli.committee_id),
    )
    .await?;

    info!("received committed info from contract");

    let p = RootProvider::<Ethereum>::connect(cli.parent_rpc_url.as_str()).await?;
    let funding_key = PrivateKeySigner::from_str(&cli.funder_private_key)?;
    let funding_addr = funding_key.address();
    for addr in comm_info.sig_key_addresses() {
        info!(%addr, "attempting to fund address");
        let nonce = p.get_transaction_count(funding_addr).await?;
        let funds = U256::from_str("1500000000000000000").expect("15.0 ETH");
        let mut tx = TxLegacy {
            chain_id: None,
            nonce,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: (*addr).into(),
            value: funds,
            input: alloy::primitives::Bytes::new(),
        };

        let sig = funding_key.sign_transaction_sync(&mut tx)?;
        let signed = tx.into_signed(sig);
        let env = TxEnvelope::Legacy(signed);
        let mut rlp = BytesMut::new();
        env.encode(&mut rlp);
        let raw_tx = rlp.freeze();
        let pending = p.send_raw_transaction(&raw_tx).await?;
        let _ = pending.get_receipt().await;
        let balance = p.get_balance(*addr).await?;
        info!(%addr, balance=%balance.to_string(), "received funds for address");
        let balance = p.get_balance(funding_addr).await?;
        info!(%funding_addr, balance=%balance.to_string(), "remaining balance from funding key");
    }

    Ok(())
}
