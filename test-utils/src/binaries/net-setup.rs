//! This executable configures network namespaces according to a configuration file.
//!
//! It creates a bridge device, *N* namespaces and virtual ethernet device pairs,
//! with one end inside the namespace.  It also applies a queuing discipline to
//! the egress traffic of each device using the configured delay and jitter
//! values. Finally, for each namespace a `resolv.conf` file is created in
//! `/etc/netns/<namespace>/` to ensure name resolution works inside the namespace.
//!
//! Here is a sample trace showing the command execution for the bridge device and
//! one namespace plus device, and finally the iptables setup.
//!
//! ```
//! > ip link add bridge type bridge
//! > ip addr add 11.0.1.0/16 dev bridge
//! > ip link set bridge up
//! > ip netns add ns-dev1
//! > ip link add dev-dev1 type veth peer name dev1
//! > ip link set dev1 up
//! > ip link set dev1 master bridge
//! > ip link set dev-dev1 netns ns-dev1
//! > ip netns exec ns-dev1 ip addr add 11.0.0.1/16 dev dev-dev1
//! > ip netns exec ns-dev1 ip link set dev-dev1 up
//! > ip netns exec ns-dev1 ip link set lo up
//! > ip netns exec ns-dev1 ip route add default via 11.0.1.0
//! > ip netns exec ns-dev1 tc qdisc add dev dev-dev1 root netem delay 50ms 50ms
//! > writing "/etc/netns/ns-dev1/resolv.conf"
//! ...
//! > iptables -t nat -A POSTROUTING -s 11.0.0.0/8 -o eth0 -j MASQUERADE
//! > iptables -I FORWARD -i eth0 -o bridge -j ACCEPT
//! > iptables -I FORWARD -i bridge -o eth0 -j ACCEPT
//! ```
//!
//! Should the setup encounter an error, manual cleanup may be required:
//!
//! 1. To remove any `resolv.conf` files, remove the sub-directories in `/etc/netns`
//! 2. To remove the bridge device, enter (as root): `ip link delete bridge`.
//! 3. To remove a virtual ethernet device, enter (as root): `ip link delete <name>`
//! 4. To remove a namespace, enter (as root): `ip netns delete <name>`.
//! 5. To remove iptables settings, enter (as root):
//!    - `iptables -t nat -D POSTROUTING -s <nat.cidr> -o <nat.device> -j MASQUERADE`
//!    - `iptables -D FORWARD -i <nat.device> -o bridge -j ACCEPT`
//!    - `iptables -D FORWARD -o <nat.device> -i bridge -j ACCEPT`

use anyhow::Result;

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    setup::go()
}

#[cfg(target_os = "linux")]
#[rustfmt::skip]
mod setup {
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

    pub fn go() -> Result<()> {
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
                    if c.nat.is_some() {
                        dev.add_resolv_conf()?
                    }
                }
                if let Some(nat) = c.nat {
                    run_command(TRACE, ["iptables",
                        "-t", "nat",
                        "-A", "POSTROUTING",
                        "-s", &nat.cidr.to_string(),
                        "-o", &nat.device,
                        "-j", "MASQUERADE"
                    ])?;
                    run_command(TRACE, ["iptables",
                        "-I", "FORWARD",
                        "-i", &nat.device,
                        "-o", "bridge",
                        "-j", "ACCEPT"
                    ])?;
                    run_command(TRACE, ["iptables",
                        "-I", "FORWARD",
                        "-i", "bridge",
                        "-o", &nat.device,
                        "-j", "ACCEPT"
                    ])?;
                }
            }
            Command::Delete { config } => {
                let t = fs::read(&config)?;
                let c: Config = toml::from_slice(&t)?;
                let b = Bridge::new(&c.bridge.name, c.bridge.cidr);
                for d in c.device {
                    let dev = Device::new(&d);
                    if c.nat.is_some() {
                        dev.del_resolv_conf()?
                    }
                    dev.delete()?;
                }
                if let Some(nat) = c.nat {
                    run_command(TRACE, ["iptables",
                        "-t", "nat",
                        "-D", "POSTROUTING",
                        "-s", &nat.cidr.to_string(),
                        "-o", &nat.device,
                        "-j", "MASQUERADE"
                    ])?;
                    run_command(TRACE, ["iptables",
                        "-D", "FORWARD",
                        "-i", &nat.device,
                        "-o", "bridge",
                        "-j", "ACCEPT"
                    ])?;
                    run_command(TRACE, ["iptables",
                        "-D", "FORWARD",
                        "-i", "bridge",
                        "-o", &nat.device,
                        "-j", "ACCEPT"
                    ])?;
                }
                b.delete()?
            }
        }
        Ok(())
    }

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

    #[derive(Debug)]
    struct Device {
        space: String,
        name: String,
        dev: String,
        cidr: Ipv4Net,
    }

    impl Device {
        fn new(cfg: &DeviceConfig) -> Self {
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

        fn add_resolv_conf(&self) -> Result<()> {
            const RESOLV_CONF: &str = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";

            let dir = PathBuf::from(format!("/etc/netns/{}", self.space));
            if !dir.exists() {
                if TRACE {
                    eprintln!("> creating {dir:?}")
                }
                fs::create_dir_all(&dir)?
            }
            let file = dir.join("resolv.conf");
            if TRACE {
                eprintln!("> writing {file:?}")
            }
            fs::write(file, RESOLV_CONF)?;
            Ok(())
        }

        fn del_resolv_conf(&self) -> Result<()> {
            let dir = PathBuf::from(format!("/etc/netns/{}", self.space));
            if dir.exists() {
                let file = dir.join("resolv.conf");
                if file.exists() {
                    if TRACE {
                        eprintln!("> removing {file:?}")
                    }
                    fs::remove_file(file)?
                }
                if TRACE {
                    eprintln!("> removing {dir:?}")
                }
                fs::remove_dir(dir)?
            }
            Ok(())
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
}
