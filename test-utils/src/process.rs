use anyhow::{Result, anyhow, bail};
use std::{ffi::OsStr, iter::once, process::Command};

pub fn run_command<I, S>(trace: bool, it: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut args = it.into_iter();
    let exe = args.next().ok_or_else(|| anyhow!("invalid command"))?;
    let mut cmd = Command::new(exe);
    for a in args {
        cmd.arg(a);
    }
    if trace {
        eprintln!(
            "> {}",
            once(cmd.get_program())
                .chain(cmd.get_args())
                .map(|os| os.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let status = cmd.status()?;
    if !status.success() {
        bail!("command not successful, status = {status:?}")
    }
    Ok(())
}
