use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use either::Either;
use multisig::CommitteeId;
use timeboost::config::{CommitteeDefinition, MemberFile};

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    committee: CommitteeId,

    #[clap(long, short)]
    start: jiff::Timestamp,

    #[clap(long, short)]
    output: PathBuf,

    members: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = CommitteeDefinition {
        id: args.committee,
        start: Either::Left(args.start),
        member: args
            .members
            .into_iter()
            .map(|path| MemberFile { config: path })
            .collect(),
    };
    config.write(args.output).await?;
    Ok(())
}
