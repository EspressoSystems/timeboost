use std::{ffi::OsStr, path::PathBuf};

use anyhow::{Result, bail};
use clap::Parser;
use tokio::{fs::read_dir, process::Command};
use tokio_util::task::TaskTracker;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    configs: PathBuf,

    #[clap(long, short)]
    committee: u64,

    #[clap(long, short)]
    timeboost: PathBuf,

    #[clap(long, short, default_value = "/tmp")]
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

    let mut commands = Vec::new();
    let mut entries = read_dir(&args.configs).await?;

    while let Some(entry) = entries.next_entry().await? {
        if Some(OsStr::new("toml")) != entry.path().extension() {
            continue;
        }
        let mut cmd = Command::new(args.timeboost.as_os_str());
        cmd.arg("--committee-id")
            .arg(args.committee.to_string())
            .arg("--https-only")
            .arg("false")
            .arg("--config")
            .arg(entry.path())
            .arg("--ignore-stamp")
            .kill_on_drop(true);
        commands.push(cmd);
    }

    let tasks = TaskTracker::new();

    for mut cmd in commands {
        tasks.spawn(async move {
            let mut child = cmd.spawn()?;
            child.wait().await
        });
    }

    tasks.close();
    tasks.wait().await;

    Ok(())
}
