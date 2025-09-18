use std::collections::BTreeMap;
use std::process::Command as StdCommand;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail, ensure};
use clap::Parser;
use test_utils::net::Config;
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
    timeboost: PathBuf,

    #[clap(long, short)]
    uid: Option<u32>,

    #[clap(long, short)]
    gid: Option<u32>,

    #[clap(long, default_value = "/tmp")]
    tmp: PathBuf,
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
                let mut cmd = StdCommand::new(args.timeboost.as_os_str());
                cmd.arg("--config").arg(entry.path()).arg("--ignore-stamp");
                commands.insert(name.to_string(), cmd);
            }
            ConfigType::Committee | ConfigType::Unknown => continue,
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(conf) = netconf {
        ensure!(conf.device.len() == commands.len());
        for d in conf.device {
            let Some(c) = commands.get_mut(&d.node) else {
                eprintln!("no command for device {} node {}", d.name, d.node);
                continue;
            };
            let mut cmd = StdCommand::new("ip");
            cmd.args(["netns", "exec", &d.namespace()]);
            if let Some((uid, gid)) = args.uid.zip(args.gid) {
                cmd.args([
                    "setpriv",
                    "--reuid",
                    &uid.to_string(),
                    "--regid",
                    &gid.to_string(),
                    "--clear-groups",
                ]);
            }
            cmd.arg(c.get_program()).args(c.get_args());
            *c = cmd;
        }
    }

    let tasks = TaskTracker::new();

    for cmd in commands.into_values() {
        tasks.spawn(async move {
            let mut child = Command::from(cmd).spawn()?;
            child.wait().await
        });
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
