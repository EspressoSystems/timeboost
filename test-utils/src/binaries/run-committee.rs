use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use rand::seq::IndexedRandom;
use test_utils::net::Config;
use test_utils::process::Cmd;
use test_utils::scenario::{Action, Scenario};
use timeboost::config::{CommitteeContract, CommitteeDefinition, HTTP_API_PORT_OFFSET, NodeConfig};
use timeboost::types::Timestamp;
use tokio::time::sleep;
use tokio::{fs, process::Command};
use tokio_util::task::TaskTracker;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    committee: PathBuf,

    #[clap(long)]
    nodes: PathBuf,

    #[clap(long, short)]
    net: Option<PathBuf>,

    #[clap(long, short)]
    scenario: Option<PathBuf>,

    #[clap(long, short, default_value = "target/release/timeboost")]
    timeboost: PathBuf,

    #[clap(long, short)]
    uid: Option<u32>,

    #[clap(long, short)]
    gid: Option<u32>,

    #[clap(long, default_value = "/tmp")]
    tmp: PathBuf,

    #[clap(flatten)]
    until: UntilArgs,

    #[clap(long)]
    times_until: Option<u64>,

    #[clap(long, short)]
    verbose: bool,

    #[clap(long, default_value_t = false)]
    ignore_stamp: bool,
}

#[derive(Debug, clap::Args)]
#[group(required = false)]
pub struct UntilArgs {
    #[clap(long)]
    until_round: Option<u64>,

    #[clap(long)]
    until_decrypt_round: Option<u64>,

    #[clap(long, default_value = "target/release/until")]
    until: PathBuf,

    #[clap(long, default_value_t = 60)]
    until_timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.tmp.is_dir() {
        bail!("{:?} is not a directory", args.tmp)
    }

    if !args.timeboost.is_file() {
        bail!("{:?} is not a file", args.timeboost)
    }

    let definition = CommitteeDefinition::read(&args.committee).await?;
    let committee = definition.to_config().await?;
    let Some(member) = committee.members.choose(&mut rand::rng()) else {
        bail!("committee {:?} has no members", args.committee)
    };

    let node = NodeConfig::read(args.nodes.join(format!("{}.toml", member.signing_key))).await?;
    let mut service = CommitteeContract::from(&node);

    let Some(committee) = service.get(committee.id).await? else {
        bail!("committee not found: {}", committee.id)
    };

    let prev_committee = if committee.effective > Timestamp::now() {
        let Some(prev) = service.prev(committee.id).await? else {
            bail!("no committee before {}", committee.id)
        };
        Some(prev)
    } else {
        None
    };

    let netconf: Option<Config> = if let Some(net) = &args.net {
        let bytes = fs::read(net).await?;
        Some(toml::from_slice(&bytes)?)
    } else {
        None
    };

    let mut commands = BTreeMap::new();

    for m in &committee.members {
        if prev_committee
            .as_ref()
            .map(|p| p.members.iter().any(|o| o.signing_key == m.signing_key))
            .unwrap_or(false)
        {
            continue;
        }
        let mut cmd = Cmd::new(&args.timeboost);
        cmd.with_arg("--node")
            .with_arg(args.nodes.join(format!("{}.toml", m.signing_key)))
            .with_arg("--committee")
            .with_arg(committee.id.to_string());
        if let Some(t) = args.times_until {
            cmd.with_args(["--times-until", &t.to_string()]);
        }
        if args.scenario.is_none() || args.ignore_stamp {
            cmd.with_arg("--ignore-stamp");
        }
        if let Some(until) = &args.until.until_round {
            let mut u = Cmd::new(args.until.until.clone());
            u.with_arg("--api")
                .with_arg(format!(
                    "http://{}",
                    m.address.clone().with_offset(HTTP_API_PORT_OFFSET)
                ))
                .with_arg("--timeout")
                .with_arg(args.until.until_timeout.to_string())
                .with_arg("--sailfish-rounds")
                .with_arg(until.to_string());
            if let Some(r) = args.until.until_decrypt_round {
                u.with_arg("--decrypt-rounds").with_arg(r.to_string());
            }
            u.with_arg("--").with_arg(cmd.exe()).with_args(cmd.args());
            cmd = u;
        }
        commands.insert(m.signing_key, cmd);
    }

    #[cfg(target_os = "linux")]
    if let Some(conf) = netconf {
        for d in conf.device {
            let Some(c) = commands.get_mut(&d.node) else {
                eprintln!("> no command for device {} node {}", d.name, d.node);
                continue;
            };
            let mut cmd = Cmd::new("ip");
            cmd.with_args(["netns", "exec", &d.namespace()]);
            if let Some((uid, gid)) = args.uid.zip(args.gid) {
                cmd.with_args([
                    "setpriv",
                    "--reuid",
                    &uid.to_string(),
                    "--regid",
                    &gid.to_string(),
                    "--clear-groups",
                ]);
            }
            cmd.with_arg(c.exe()).with_args(c.args());
            *c = cmd;
        }
    }

    let tasks = TaskTracker::new();

    if let Some(path) = &args.scenario {
        let bytes = fs::read(path).await?;
        let scenario: Scenario = toml::from_slice(&bytes)?;
        for s in &scenario.steps {
            match &s.action {
                Action::StartNode { node, .. } | Action::StopNode { node, .. } => {
                    if !commands.contains_key(node) {
                        bail!("node {node} of scenario {path:?} not found");
                    }
                }
                Action::Remove { .. } => {}
            }
        }
        let mut nodes = BTreeMap::new();
        for s in &scenario.steps {
            if !s.delay.is_zero() {
                sleep(s.delay.try_into()?).await
            }
            if args.verbose {
                eprintln!("> executing scenario action: {}", s.action);
            }
            match &s.action {
                Action::Remove { files } => {
                    for f in files {
                        if f.is_file() {
                            if args.verbose {
                                eprintln!(">> removing file {f:?}");
                            }
                            fs::remove_file(f).await?
                        }
                    }
                }
                Action::StartNode { node, .. } => {
                    let cmd = commands
                        .get(node)
                        .cloned()
                        .ok_or_else(|| anyhow!("{node:?} not found"))?;
                    nodes.insert(
                        node,
                        tasks.spawn(async move {
                            let mut cmd = Command::from(cmd);
                            cmd.kill_on_drop(true);
                            let mut child = cmd.spawn()?;
                            child.wait().await
                        }),
                    );
                }
                Action::StopNode { node, .. } => {
                    let handle = nodes
                        .remove(node)
                        .ok_or_else(|| anyhow!("{node:?} not running"))?;
                    handle.abort();
                }
            }
        }
    } else {
        for (node, cmd) in commands {
            if args.verbose {
                eprintln!("spawning timeboost node {node}: \"{cmd}\"");
            }
            let mut command = Command::from(&cmd);
            command.kill_on_drop(true);
            let mut child = command
                .spawn()
                .with_context(|| format!("failed to spawn \"{cmd}\""))?;
            tasks.spawn(async move { child.wait().await });
        }
    }

    tasks.close();
    tasks.wait().await;

    Ok(())
}
