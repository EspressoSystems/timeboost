use std::str::FromStr;

use alloy::{
    consensus::{
        SignableTransaction, TxEnvelope, TxLegacy, crypto::secp256k1::public_key_to_address,
    },
    network::{Ethereum, TxSignerSync},
    primitives::{Address, U256},
    providers::{Provider, RootProvider},
    rlp::{BytesMut, Encodable},
    signers::{k256::ecdsa::VerifyingKey, local::PrivateKeySigner},
};
use anyhow::{Result, bail};
use clap::Parser;
use multisig::CommitteeId;
use timeboost::config::config_service;
use timeboost_utils::types::logging;
use tracing::info;
use url::Url;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long, short)]
    parent_rpc_url: Url,

    #[clap(long, default_value = "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35")]
    key_manager_contract: Address,

    #[clap(
        long,
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    funder_private_key: String,

    #[clap(long, default_value_t = Default::default())]
    committee_id: CommitteeId,

    #[clap(long)]
    config_service: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let cli = Cli::parse();

    let mut service = config_service(&cli.config_service).await?;

    let Some(committee) = service.get(cli.committee_id).await? else {
        bail!("committee not found: {}", cli.committee_id)
    };

    info!("received committed info from contract");

    let p = RootProvider::<Ethereum>::connect(cli.parent_rpc_url.as_str()).await?;
    let funding_key = PrivateKeySigner::from_str(&cli.funder_private_key)?;
    let funding_addr = funding_key.address();
    for member in committee.members {
        let addr = {
            let pubkey = VerifyingKey::from_sec1_bytes(&member.signing_key.to_bytes())?;
            public_key_to_address(pubkey)
        };
        info!(%addr, "attempting to fund address");
        let nonce = p.get_transaction_count(funding_addr).await?;
        let funds = U256::from_str("1500000000000000000").expect("15.0 ETH");
        let mut tx = TxLegacy {
            chain_id: None,
            nonce,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: addr.into(),
            value: funds,
            input: alloy::primitives::Bytes::new(),
        };

        let sig = funding_key.sign_transaction_sync(&mut tx)?;
        let signed = tx.into_signed(sig);
        let env = TxEnvelope::Legacy(signed);
        let mut rlp = BytesMut::new();
        env.encode(&mut rlp);
        let pending = p.send_raw_transaction(&rlp.freeze()).await?;
        let _ = pending.get_receipt().await;
        
        let balance = p.get_balance(addr).await?;
        info!(%addr, balance=%balance, "received funds for address");
        
        let balance = p.get_balance(funding_addr).await?;
        info!(%funding_addr, balance=%balance, "remaining balance from funding key");
    }

    Ok(())
}
