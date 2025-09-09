use std::ffi::OsStr;
use std::process::exit;

use anyhow::{Result, anyhow};
use clap::Parser;
use tokio::process::Command;
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    with: String,
    main: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut with = command(args.with.split_whitespace())?.spawn()?;
    let mut main = command(args.main)?.spawn()?;

    let mut intr = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut quit = signal(SignalKind::quit())?;

    select! {
        status = main.wait() => {
            let _ = with.kill().await;
            exit(status?.code().unwrap_or_default())
        }
        _ = with.wait() => {
            let _ = main.kill().await;
            exit(-1)
        }
        _ = intr.recv() => {
            let _ = main.kill().await;
            let _ = with.kill().await;
        }
        _ = term.recv() => {
            let _ = main.kill().await;
            let _ = with.kill().await;
        }
        _ = quit.recv() => {
            let _ = main.kill().await;
            let _ = with.kill().await;
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
    Ok(cmd)
}
