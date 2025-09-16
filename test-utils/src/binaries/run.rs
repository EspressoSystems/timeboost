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
    /// Commands to run to completion.
    #[clap(long, short, value_parser = parse_command_line)]
    run: Vec<Commandline>,

    /// Commands to run concurrently.
    #[clap(long, short, value_parser = parse_command_line)]
    spawn: Vec<Commandline>,

    /// Optional timeout main command in seconds.
    #[clap(long, short)]
    timeout: Option<u64>,

    #[clap(long, short)]
    verbose: bool,

    /// Main command to execute.
    main: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    args.spawn.iter_mut().for_each(|c| c.sync = false);

    let mut commands = args.run;
    commands.append(&mut args.spawn);
    commands.sort();

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    let mut helpers = JoinSet::<Result<ExitStatus>>::new();

    for commandline in commands {
        if args.verbose {
            let joined = commandline.args.join(" ");
            if commandline.sync {
                eprintln!("running command: {joined}");
            } else {
                eprintln!("spawning command: {joined}");
            }
        }

        let mut pg = ProcessGroup::spawn(&commandline.args)?;
        if commandline.sync {
            let status = select! {
                s = pg.wait()   => s?,
                _ = term.recv() => return Ok(()),
                _ = intr.recv() => return Ok(()),
            };
            if !status.success() {
                bail!("{:?} failed with {:?}", commandline.args, status.code());
            }
        } else {
            helpers.spawn(async move {
                let mut pg = ProcessGroup::spawn(&commandline.args)?;
                let status = pg.wait().await?;
                Ok(status)
            });
        }
    }

    if args.verbose {
        eprintln!("spawning command: {}", args.main.join(" "))
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
        _ = timeout     => bail!("timeout")
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Commandline {
    prio: u8,
    args: Vec<String>,
    sync: bool,
}

fn parse_command_line(s: &str) -> Result<Commandline> {
    let (p, a) = s.split_once(':').unwrap_or(("0", s));
    // Replace __SPACE__ with actual spaces, then split like shell would
    let parts = shell_words::split(a)?
        .into_iter()
        .map(|arg| arg.replace("__SPACE__", " "))
        .collect();
    Ok(Commandline {
        prio: p.parse()?,
        args: parts,
        sync: true,
    })
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
        cmd.args(args);
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
