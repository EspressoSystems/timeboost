use std::{ffi::OsStr, process::ExitStatus};

use anyhow::{Result, anyhow, bail};
use clap::Parser;
use tokio::select;
use tokio::{
    process::{Child, Command},
    task::JoinSet,
};

#[derive(Parser, Debug)]
struct Args {
    /// Commands to run to completion first.
    #[clap(long, short)]
    exec: Vec<String>,

    /// Commands to run concurrently.
    #[clap(long, short)]
    with: Vec<String>,

    /// Main command to execute.
    main: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    for exe in &args.exec {
        let status = command(exe.split_whitespace())?.status().await?;
        if !status.success() {
            bail!("{exe:?} failed with {:?}", status.code());
        }
    }

    let mut helpers = JoinSet::<Result<ExitStatus>>::new();
    for w in args.with {
        helpers.spawn(async move {
            let mut c = spawn_command(w.split_whitespace())?;
            let status = c.wait().await?;
            Ok(status)
        });
    }

    let mut main = spawn_command(args.main)?;

    select! {
        status = main.wait() => {
            let status = status?;
            if !status.success() {
                bail!("command failed with {:?}", status)
            }
        },
        Some(status) = helpers.join_next() => {
            let status = status??;
            bail!("helper command exited before main with status {:?}", status)
        }
    }

    Ok(())
}

fn command<I, S>(it: I) -> Result<Command>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut args = it.into_iter();
    let exe = args
        .next()
        .ok_or_else(|| anyhow!("invalid command-line args"))?;
    let mut cmd = Command::new(exe);
    for a in args {
        cmd.arg(a);
    }
    cmd.kill_on_drop(true);
    Ok(cmd)
}

fn spawn_command<I, S>(it: I) -> Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    command(it)?.spawn().map_err(|e| e.into())
}
