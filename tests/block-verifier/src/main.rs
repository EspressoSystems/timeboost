use alloy::{
    eips::BlockNumberOrTag,
    network::{Ethereum, Network},
    providers::{Provider, RootProvider},
    rpc::types::Block,
};
use anyhow::{Context, Result};
use clap::Parser;
use futures::future::join_all;
use timeboost_utils::types::logging::init_logging;
use tracing::{error, info};

#[derive(Parser, Debug)]
struct Cli {
    /// Nitro node URLs used for gas estimations and getting nonce when sending transactions
    /// Can be specified multiple times: --nitro-url url1 --nitro-url url2
    #[clap(
        long,
        default_value = "http://localhost:8547;http://localhost:8647",
        use_value_delimiter = true,
        value_delimiter = ';'
    )]
    nitro_urls: Vec<String>,
}

async fn connect_to_chain<N: Network>(urls: &[String]) -> Result<Vec<RootProvider<N>>> {
    let mut p = Vec::new();
    for url in urls {
        p.push(RootProvider::<N>::connect(url).await?)
    }
    Ok(p)
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();

    let providers = connect_to_chain::<Ethereum>(&cli.nitro_urls).await?;

    // take the minimum block in to avoid race conditions
    let min_block = join_all(providers.iter().map(|p| async {
        p.get_block_number()
            .await
            .context("provider request failed")
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<u64>>>()?
    .into_iter()
    .min()
    .context("failed to get min block")?;

    for i in 0..=min_block {
        info!(num = %i, "getting block number");
        let blocks = join_all(providers.iter().map(|p| async {
            p.get_block_by_number(BlockNumberOrTag::Number(i))
                .await
                .context("provider request failed")
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<Option<Block>>>>()?;
        let first_block = blocks
            .first()
            .and_then(|b| b.as_ref())
            .ok_or_else(|| anyhow::anyhow!("no blocks received from any provider"))?;
        for (i, block) in blocks.iter().enumerate().skip(1) {
            let b = block
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("provider returned no block"))?;
            if b != first_block {
                error!(
                    block_a = ?b,
                    block_b = ?first_block,
                    "❌ block mismatch between state"
                );
                anyhow::bail!(
                    "block mismatch between blocks: left: {:?}, right: {:?}",
                    b,
                    first_block
                );
            }
            if i == blocks.len() - 1 {
                info!(block_hash = %b.hash(), txns = ?b.transactions, "✅ verified block");
            }
        }
    }

    Ok(())
}
