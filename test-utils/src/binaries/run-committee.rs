use std::collections::{BTreeMap, HashSet};
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow, bail, ensure};
use clap::Parser;
use test_utils::net::Config;
use test_utils::process::Cmd;
use test_utils::scenario::{Action, Scenario};
use timeboost::config::CommitteeConfig;
use tokio::time::sleep;

use tokio::{
    fs::{self, read_dir},
    process::Command,
};
use tokio_util::task::TaskTracker;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    configs: PathBuf,

    #[clap(long, short)]
    scenario: Option<PathBuf>,

    #[clap(long, short, default_value = "target/release/timeboost")]
    timeboost: PathBuf,

    #[clap(long)]
    max_nodes: usize,

    #[clap(long, short)]
    uid: Option<u32>,

    #[clap(long, short)]
    gid: Option<u32>,

    #[clap(long, default_value = "/tmp")]
    tmp: PathBuf,

    #[clap(long)]
    until: Option<u64>,

    #[clap(long)]
    required_decrypt_rounds: Option<u64>,

    #[clap(long)]
    times_until: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.configs.is_dir() {
        bail!("{:?} is not a directory", args.configs)
    }

    if !args.tmp.is_dir() {
        bail!("{:?} is not a directory", args.tmp)
    }

    if !args.timeboost.is_file() {
        bail!("{:?} is not a file", args.timeboost)
    }

    let mut netconf: Option<Config> = None;
    let mut committee: Option<CommitteeConfig> = None;
    let mut commands = BTreeMap::new();
    let mut entries = read_dir(&args.configs).await?;

    while let Some(entry) = entries.next_entry().await? {
        match ConfigType::read(&entry.path()) {
            ConfigType::Network => {
                ensure!(netconf.is_none());
                let bytes = fs::read(&entry.path()).await?;
                netconf = Some(toml::from_slice(&bytes)?);
            }
            ConfigType::Node(name) => {
                let mut cmd = Cmd::new(&args.timeboost);
                cmd.with_arg("--config").with_arg(entry.path());
                if let Some(until) = args.until {
                    cmd.with_arg("--until").with_arg(until.to_string());
                }
                if let Some(r) = args.required_decrypt_rounds {
                    cmd.with_arg("--required-decrypt-rounds")
                        .with_arg(r.to_string());
                }
                if let Some(t) = args.times_until {
                    cmd.with_arg("--times-until").with_arg(t.to_string());
                }
                commands.insert(name.to_string(), cmd);
            }
            ConfigType::Committee => {
                ensure!(committee.is_none());
                committee = Some(CommitteeConfig::read(&entry.path()).await?)
            }
            ConfigType::Unknown => continue,
        }
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

    let Some(conf) = committee else {
        bail!("missing committee config")
    };

    let subset: HashSet<String> = conf
        .members
        .into_iter()
        .take(args.max_nodes)
        .map(|m| m.node)
        .collect();

    let tasks = TaskTracker::new();

    if let Some(path) = &args.scenario {
        let bytes = fs::read(path).await?;
        let scenario: Scenario = toml::from_slice(&bytes)?;
        for s in &scenario.steps {
            match &s.action {
                Action::StartNode { node, .. } | Action::StopNode { node, .. } => {
                    if !subset.contains(node) {
                        bail!("can not resolve node {node} of scenario {path:?}");
                    }
                    if !commands.contains_key(node) {
                        bail!("node {node} of scenario {path:?} not found");
                    }
                }
                Action::Remove { .. } | Action::Exit => {}
            }
        }
        let mut nodes = BTreeMap::new();
        for s in &scenario.steps {
            if !s.delay.is_zero() {
                sleep(s.delay.try_into()?).await
            }
            eprintln!("> executing scenario action: {}", s.action);
            match &s.action {
                Action::Remove { files } => {
                    for f in files {
                        if f.is_file() {
                            eprintln!(">> removing file {f:?}");
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
                Action::Exit => return Ok(()),
            }
        }
    } else {
        for (node, cmd) in commands {
            if !subset.contains(&node) {
                eprintln!("ignoring node {node} command");
                continue;
            }
            tasks.spawn(async move {
                let mut child = Command::from(cmd).spawn()?;
                child.wait().await
            });
        }
    }

    tasks.close();
    tasks.wait().await;

    Ok(())
}

enum ConfigType<'a> {
    Committee,
    Node(&'a str),
    Network,
    Unknown,
}

impl<'a> ConfigType<'a> {
    fn read(p: &'a Path) -> Self {
        if p.extension() != Some(OsStr::new("toml")) {
            return ConfigType::Unknown;
        }
        let Some(name) = p.file_stem().and_then(|n| n.to_str()) else {
            return ConfigType::Unknown;
        };
        if name.starts_with("node") {
            return ConfigType::Node(name);
        }
        if name == "committee" {
            return ConfigType::Committee;
        }
        if name == "net" {
            return ConfigType::Network;
        }
        ConfigType::Unknown
    }
}
