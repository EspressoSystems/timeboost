#![cfg_attr(rustfmt, rustfmt_skip)]

use std::{fs, path::PathBuf};

use anyhow::{Result, ensure};
use clap::Parser;
use ipnet::Ipv4Net;
use jiff::Span;
use test_utils::{
    net::{Config, DeviceConfig},
    process::run_command,
};

const TRACE: bool = true;

#[derive(Debug, Parser)]
enum Command {
    System {
        #[clap(long, action = clap::ArgAction::Set)]
        forward_ipv4: bool,
    },
    Create {
        #[clap(long, short)]
        config: PathBuf,
    },
    Delete {
        #[clap(long, short)]
        config: PathBuf,
    },
}

fn main() -> Result<()> {
    match Command::parse() {
        Command::System { forward_ipv4 } => {
            let v = u8::from(forward_ipv4);
            run_command(TRACE, ["sysctl", "-w", &format!("net.ipv4.ip_forward={v}")])?
        }
        Command::Create { config } => {
            let t = fs::read(&config)?;
            let c: Config = toml::from_slice(&t)?;
            let b = Bridge::new(&c.bridge.name, c.bridge.cidr);
            b.create()?;
            for d in c.device {
                let dev = Device::new(&d);
                dev.create(&b)?;
                if !d.delay.is_zero() {
                    dev.delay(&d.delay, &d.jitter)?
                }
            }
            if let Some(nat) = c.nat {
                run_command(TRACE, ["iptables",
                    "-t", &nat.table,
                    "-A", "POSTROUTING",
                    "-s", &nat.cidr.to_string(),
                    "-o", &nat.device,
                    "-j", "MASQUERADE"
                ])?
            }
        }
        Command::Delete { config } => {
            let t = fs::read(&config)?;
            let c: Config = toml::from_slice(&t)?;
            let b = Bridge::new(&c.bridge.name, c.bridge.cidr);
            for d in c.device {
                Device::new(&d).delete()?
            }
            b.delete()?;
            if let Some(nat) = c.nat {
                run_command(TRACE, ["iptables", "-t", &nat.table, "-F"])?
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Device {
    space: String,
    name: String,
    dev: String,
    cidr: Ipv4Net,
}

impl Device {
    fn new(cfg: &DeviceConfig) -> Device {
        Self {
            space: cfg.namespace(),
            dev: cfg.device(),
            cidr: cfg.cidr,
            name: cfg.name.clone(),
        }
    }

    fn create(&self, b: &Bridge) -> Result<()> {
        ensure!(b.net.contains(&self.cidr));
        run_command(TRACE, ["ip", "netns", "add", &self.space])?;
        run_command(TRACE, ["ip", "link", "add", &self.dev, "type", "veth", "peer", "name", &self.name])?;
        run_command(TRACE, ["ip", "link", "set", &self.name, "up"])?;
        run_command(TRACE, ["ip", "link", "set", &self.name, "master", &b.name])?;
        run_command(TRACE, ["ip", "link", "set", &self.dev, "netns", &self.space])?;
        run_command(TRACE, ["ip", "netns", "exec", &self.space, "ip", "addr", "add", &self.cidr.to_string(), "dev", &self.dev])?;
        run_command(TRACE, ["ip", "netns", "exec", &self.space, "ip", "link", "set", &self.dev, "up"])?;
        run_command(TRACE, ["ip", "netns", "exec", &self.space, "ip", "link", "set", "lo", "up"])?;
        run_command(TRACE, ["ip", "netns", "exec", &self.space, "ip", "route", "add", "default",  "via",  &b.net.addr().to_string()])
    }

    fn delay(&self, delay: &Span, jitter: &Span) -> Result<()> {
        let d = format!("{}ms", delay.get_milliseconds());
        let j = format!("{}ms", jitter.get_milliseconds());
        run_command(TRACE, [
            "ip", "netns", "exec", &self.space,
            "tc", "qdisc", "add", "dev", &self.dev, "root", "netem", "delay", &d, &j
        ])
    }

    fn delete(self) -> Result<()> {
        run_command(TRACE, ["ip", "link", "delete", &self.name])?;
        run_command(TRACE, ["ip", "netns", "delete", &self.space])
    }
}

#[derive(Debug)]
struct Bridge {
    name: String,
    net: Ipv4Net,
}

impl Bridge {
    fn new(name: &str, ip: Ipv4Net) -> Self {
        Self { name: name.to_string(), net: ip }
    }

    fn create(&self) -> Result<()> {
        run_command(TRACE, ["ip", "link", "add", &self.name, "type", "bridge"])?;
        run_command(TRACE, ["ip", "addr", "add", &self.net.to_string(), "dev", "bridge"])?;
        run_command(TRACE, ["ip", "link", "set", &self.name, "up"])
    }

    fn delete(self) -> Result<()> {
        run_command(TRACE, ["ip", "link", "delete", &self.name])
    }
}
