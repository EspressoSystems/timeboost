use std::future::pending;
use std::ops::{Deref, DerefMut};
use std::process::ExitStatus;
use std::time::Duration;

use anyhow::{Result, anyhow, bail, ensure};
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

    /// Commands to run as root to completion.
    #[clap(long, short, value_parser = parse_command_line)]
    run_as_root: Vec<Commandline>,

    /// Commands to run concurrently as root user.
    #[clap(long, short, value_parser = parse_command_line)]
    spawn_as_root: Vec<Commandline>,

    #[clap(long, short)]
    env: Vec<String>,

    #[clap(long)]
    clear_env: bool,

    /// Optional timeout main command in seconds.
    #[clap(long, short)]
    timeout: Option<u64>,

    #[clap(long, short)]
    verbose: bool,

    /// Optional user ID to run processes.
    #[clap(long)]
    uid: Option<u32>,

    /// Optional group ID to run processes.
    #[clap(long)]
    gid: Option<u32>,

    /// Main command to execute.
    main: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();
    ensure!(!args.main.is_empty());
    args.run_as_root.iter_mut().for_each(|c| c.root = true);
    args.spawn.iter_mut().for_each(|c| c.sync = false);
    args.spawn_as_root.iter_mut().for_each(|c| {
        c.root = true;
        c.sync = false
    });

    let mut commands = args.run;
    commands.append(&mut args.run_as_root);
    commands.append(&mut args.spawn);
    commands.append(&mut args.spawn_as_root);
    commands.sort();

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    let mut helpers = JoinSet::<Result<ExitStatus>>::new();

    for cmd in commands {
        let uid = cmd.root.then_some(0).or(args.uid);
        let gid = cmd.root.then_some(0).or(args.gid);
        if args.verbose {
            if cmd.sync {
                eprintln!("running command: {}", cmd.args)
            } else {
                eprintln!("spawning command: {}", cmd.args)
            }
        }
        if cmd.sync {
            let mut pg = ProcessGroup::spawn(
                uid,
                gid,
                args.clear_env,
                &args.env,
                cmd.args.split_whitespace(),
            )?;
            let status = select! {
                s = pg.wait()   => s?,
                _ = term.recv() => return Ok(()),
                _ = intr.recv() => return Ok(()),
            };
            if !status.success() {
                bail!("{:?} failed with {:?}", cmd.args, status.code());
            }
        } else {
            let mut pg = ProcessGroup::spawn(
                uid,
                gid,
                args.clear_env,
                &args.env,
                cmd.args.split_whitespace(),
            )?;
            helpers.spawn(async move {
                let status = pg.wait().await?;
                Ok(status)
            });
        }
    }

    if args.verbose {
        eprintln!("spawning command: {}", args.main.join(" "))
    }

    let mut main = ProcessGroup::spawn(args.uid, args.gid, args.clear_env, &args.env, args.main)?;

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
    args: String,
    sync: bool,
    root: bool,
}

fn parse_command_line(s: &str) -> Result<Commandline> {
    let (p, a) = s.split_once('|').unwrap_or(("0", s));
    Ok(Commandline {
        prio: p.parse()?,
        args: a.to_string(),
        sync: true,
        root: false,
    })
}

/// Every command is spawned into its own, newly created process group.
struct ProcessGroup(Child, Pid);

impl ProcessGroup {
    fn spawn<I, S>(
        uid: Option<u32>,
        gid: Option<u32>,
        clear: bool,
        env: &[String],
        it: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String> + AsRef<str>,
    {
        let mut args = it.into_iter();
        let exe = args
            .next()
            .ok_or_else(|| anyhow!("invalid command-line args"))?;
        let mut cmd = Command::new(exe.as_ref());
        let mut buf: Option<Vec<String>> = None;
        for a in args {
            if let Some(b) = &mut buf {
                let mut a = a.into();
                if a.ends_with("'") {
                    a.pop();
                    b.push(a);
                    cmd.arg(b.join(" "));
                    buf = None
                } else {
                    b.push(a);
                }
            } else if a.as_ref().starts_with("'") {
                let mut a = a.into();
                a.remove(0);
                buf = Some(vec![a]);
            } else {
                cmd.arg(a.as_ref());
            }
        }
        cmd.process_group(0);
        if let Some(id) = uid {
            cmd.uid(id);
        }
        if let Some(id) = gid {
            cmd.gid(id);
        }
        if clear {
            cmd.env_clear();
            for e in env {
                match std::env::var(e) {
                    Ok(v) => {
                        cmd.env(e, v);
                    }
                    Err(err) => eprintln!("error getting env var {e}: {err}"),
                }
            }
        }
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
