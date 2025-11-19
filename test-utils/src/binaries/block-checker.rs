use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Result, bail};
use clap::Parser;
use either::Either;
use multisig::rand::{self, seq::IndexedRandom};
use robusta::{Client, Config, Watcher, espresso_types::NamespaceId};
use sailfish::types::CommitteeVec;
use timeboost::config::{CommitteeDefinition, NodeConfig};
use timeboost_utils::logging::init_logging;
use tracing::info;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    nodes: PathBuf,

    #[clap(long)]
    committee: PathBuf,

    #[clap(long, short)]
    blocks: usize,

    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    https_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let args = Args::parse();

    let definition = CommitteeDefinition::read(&args.committee).await?;
    let committee = definition.to_config().await?;
    let committees = CommitteeVec::<1>::new(committee.sailfish().committee().clone());
    let Some(member) = committee.members.choose(&mut rand::rng()) else {
        bail!("committee {:?} has no members", args.committee)
    };

    let node = NodeConfig::read(args.nodes.join(format!("{}.toml", member.signing_key))).await?;

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
