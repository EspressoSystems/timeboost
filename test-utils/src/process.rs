use anyhow::{Result, anyhow, bail};
use std::{
    ffi::{OsStr, OsString},
    fmt,
    iter::once,
    process::Command,
};

pub fn run_command<I, S>(trace: bool, it: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut args = it.into_iter();
    let exe = args.next().ok_or_else(|| anyhow!("invalid command"))?;
    let mut cmd = Cmd::new(exe);
    cmd.with_args(args).trace(trace);
    cmd.execute()
}

#[derive(Debug, Clone)]
pub struct Cmd {
    exe: OsString,
    args: Vec<OsString>,
    trace: bool,
}

impl Cmd {
    pub fn new<S: Into<OsString>>(exe: S) -> Self {
        Self {
            exe: exe.into(),
            args: Vec::new(),
            trace: false,
        }
    }

    pub fn trace(&mut self, v: bool) -> &mut Self {
        self.trace = v;
        self
    }

    pub fn exe(&self) -> &OsStr {
        &self.exe
    }

    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    pub fn with_arg<S: Into<OsString>>(&mut self, a: S) -> &mut Self {
        self.args.push(a.into());
        self
    }

    pub fn with_args<I, S>(&mut self, it: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(it.into_iter().map(|s| s.into()));
        self
    }

    pub fn execute(self) -> Result<()> {
        if self.trace {
            eprintln!("> {self}");
        }
        let mut cmd = Command::new(self.exe);
        cmd.args(self.args);
        let status = cmd.status()?;
        if !status.success() {
            bail!("command not successful, status = {status:?}")
        }
        Ok(())
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = once(self.exe())
            .chain(self.args().iter().map(|s| &**s))
            .map(|os| os.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        write!(f, "{s}")
    }
}

impl From<Cmd> for std::process::Command {
    fn from(c: Cmd) -> Self {
        let mut cmd = std::process::Command::new(c.exe);
        cmd.args(c.args);
        cmd
    }
}

impl From<Cmd> for tokio::process::Command {
    fn from(c: Cmd) -> Self {
        let mut cmd = tokio::process::Command::new(c.exe);
        cmd.args(c.args);
        cmd
    }
}
