use std::{collections::BTreeSet, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use either::Either;
use multisig::Committee;
use robusta::{Client, Config, Watcher, espresso_types::NamespaceId};
use sailfish::types::CommitteeVec;
use timeboost::config::{CommitteeConfig, NodeConfig};
use timeboost_utils::types::logging::init_logging;
use tracing::{debug, info};

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    configs: PathBuf,

    #[clap(long)]
    max_nodes: usize,

    #[clap(long, short)]
    blocks: usize,

    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    https_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();

    let committees = {
        let conf = CommitteeConfig::read(args.configs.join("committee.toml")).await?;
        let mems = conf
            .members
            .into_iter()
            .take(args.max_nodes)
            .enumerate()
            .map(|(i, m)| (i as u8, m.signing_key));
        CommitteeVec::<1>::new(Committee::new(conf.id, mems))
    };

    let node = NodeConfig::read(args.configs.join("node_0.toml")).await?;

    let conf = Config::builder()
        .https_only(args.https_only)
        .base_url(node.espresso.base_url)
        .builder_base_url(node.espresso.builder_base_url)
        .wss_base_url(node.espresso.websockets_base_url)
        .label("block-checker")
        .build();

    let client = Client::new(conf.clone());
    let height = client.height().await?;
    let nspace = NamespaceId::from(node.chain.namespace);

    let mut watcher = Watcher::new(conf, height, nspace);
    let mut set = BTreeSet::new();
    let mut offset = 0;

    while offset < args.blocks {
        let Either::Right(hdr) = watcher.next().await else {
            continue;
        };
        debug!(height = %hdr.height(), "inspecting header");
        set.extend(client.verified(nspace, &hdr, &committees).await);
        let start = set.iter().skip(offset);
        offset += start
            .clone()
            .zip(start.skip(1))
            .take_while(|(a, b)| a.1 + 1 == b.1)
            .count();
        info!(blocks = %offset, "validated")
    }

    Ok(())
}
