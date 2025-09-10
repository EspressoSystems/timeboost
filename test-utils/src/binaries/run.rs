use std::future::pending;
use std::ops::{Deref, DerefMut};
use std::time::Duration;
use std::{ffi::OsStr, process::ExitStatus};

use anyhow::{Result, anyhow, bail};
use clap::Parser;
use futures::FutureExt;
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::sleep;
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

    /// Optional timeout in seconds.
    #[clap(long, short)]
    timeout: Option<u64>,

    /// Main command to execute.
    main: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;

    for exe in &args.exec {
        let mut pg = ProcessGroup::spawn(exe.split_whitespace())?;
        let status = select! {
            s = pg.wait()   => s?,
            _ = term.recv() => return Ok(()),
            _ = intr.recv() => return Ok(()),
        };
        if !status.success() {
            bail!("{exe:?} failed with {:?}", status.code());
        }
    }

    let mut helpers = JoinSet::<Result<ExitStatus>>::new();
    for w in args.with {
        helpers.spawn(async move {
            let mut pg = ProcessGroup::spawn(w.split_whitespace())?;
            let status = pg.wait().await?;
            Ok(status)
        });
    }

    let mut main = ProcessGroup::spawn(args.main)?;

    let timeout = if let Some(d) = args.timeout {
        sleep(Duration::from_secs(d)).boxed()
    } else {
        pending().boxed()
    };

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
        _ = term.recv() => {}
        _ = intr.recv() => {}
        _ = timeout     => eprintln!("timeout")
    }

    Ok(())
}

/// Every command is spawned into its own, newly created process group.
struct ProcessGroup(Child, Pid);

impl ProcessGroup {
    fn spawn<I, S>(it: I) -> Result<Self>
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
        cmd.process_group(0);
        let child = cmd.spawn()?;
        let id = child.id().ok_or_else(|| anyhow!("child already exited"))?;
        let pid = Pid::from_raw(id.try_into()?).ok_or_else(|| anyhow!("invalid pid"))?;
        Ok(Self(child, pid))
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let _ = kill_process_group(self.1, Signal::KILL);
    }
}

impl Deref for ProcessGroup {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ProcessGroup {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
