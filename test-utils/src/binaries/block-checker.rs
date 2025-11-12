use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Result, bail};
use clap::Parser;
use either::Either;
use multisig::CommitteeId;
use robusta::{Client, Config, Watcher, espresso_types::NamespaceId};
use sailfish::types::CommitteeVec;
use timeboost::config::{NodeConfig, config_service};
use timeboost_utils::types::logging::init_logging;
use tracing::info;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    node: PathBuf,

    #[clap(long)]
    committee: CommitteeId,

    #[clap(long)]
    config_service: String,

    #[clap(long, short)]
    blocks: usize,

    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    https_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();
    let node = NodeConfig::read(&args.node).await?;

    let mut service = config_service(&args.config_service).await?;
    let committees = {
        let Some(conf) = service.get(args.committee).await? else {
            bail!("no committee found for id {}", args.committee)
        };
        CommitteeVec::<1>::new(conf.sailfish().committee().clone())
    };

    let conf = Config::builder()
        .https_only(args.https_only)
        .base_url(node.espresso.base_url)
        .maybe_builder_base_url(node.espresso.builder_base_url)
        .wss_base_url(node.espresso.websockets_base_url)
        .label("block-checker")
        .build();

    let client = Client::new(conf.clone());
    let height = client.height().await?;
    let nspace = NamespaceId::from(node.espresso.namespace);

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
