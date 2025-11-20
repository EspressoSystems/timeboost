use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use either::Either;
use reqwest::Url;
use robusta::{Client, Config, Watcher, espresso_types::NamespaceId};
use sailfish::types::CommitteeVec;
use timeboost::config::{ChainConfig, CommitteeContract};
use timeboost_utils::logging::init_logging;
use tracing::info;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    chain: PathBuf,

    #[clap(long, short)]
    namespace: u64,

    #[clap(long, short)]
    espresso_base_url: Url,

    #[clap(long, short)]
    espresso_websocket_base_url: Url,

    #[clap(long, short)]
    espresso_builder_base_url: Option<Url>,

    #[clap(long, short)]
    blocks: usize,

    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    https_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();

    let chain_config = ChainConfig::read(&args.chain)
        .await
        .with_context(|| format!("could not read chain config {:?}", args.chain))?;
    let mut contract = CommitteeContract::from(&chain_config);

    let Ok(committee_config) = contract.active().await else {
        bail!("no active committee");
    };
    let committees = CommitteeVec::<1>::new(committee_config.committee());

    let conf = Config::builder()
        .https_only(args.https_only)
        .base_url(args.espresso_base_url)
        .maybe_builder_base_url(args.espresso_builder_base_url)
        .wss_base_url(args.espresso_websocket_base_url)
        .label("block-checker")
        .build();

    let client = Client::new(conf.clone());
    let height = client.height().await?;
    let nspace = NamespaceId::from(args.namespace);

    let mut watcher = Watcher::new(conf, height, nspace);
    let mut set = BTreeSet::new();
    let mut offset = 0;

    while offset < args.blocks {
        let Either::Right(hdr) = watcher.next().await else {
            continue;
        };
        info!(height = %hdr.height(), "inspecting header");
        set.extend(
            client
                .verified(nspace, &hdr, &committees)
                .await
                .map(|(b, _)| b),
        );
        let start = set.iter().skip(offset);
        offset += start
            .clone()
            .zip(start.skip(1))
            .take_while(|(a, b)| **a + 1 == **b)
            .count();
        info!(%offset, total = %set.len(), "validated")
    }

    Ok(())
}
