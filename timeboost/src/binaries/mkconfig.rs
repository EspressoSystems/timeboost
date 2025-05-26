use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU8;
use std::{io, iter};

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use cliquenet::Address;
use multisig::x25519;
use timeboost_crypto::{DecryptionScheme, TrustedKeyMaterial};
use timeboost_utils::bs58_encode;
use timeboost_utils::keyset::{KeysetConfig, NodeInfo, PrivateKeys, PublicDecInfo};
use timeboost_utils::types::logging;

#[derive(Clone, Debug, Parser)]
struct Cli {
    #[clap(long, short)]
    num: NonZeroU8,

    #[clap(long, short)]
    sailfish_base_addr: Address,

    #[clap(long, short)]
    decrypt_base_addr: Address,

    #[clap(long, short)]
    producer_base_addr: Address,

    #[clap(long, short, default_value = "increment-port")]
    mode: Mode,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Mode {
    #[default]
    IncrementPort,
    IncrementAddress,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    logging::init_logging();

    let tkm = DecryptionScheme::trusted_keygen(cli.num.into());

    let mut cfg = KeysetConfig {
        keyset: mk_node_infos(&tkm).collect(),
        dec_keyset: PublicDecInfo {
            pubkey: bs58_encode(&tkm.0.to_bytes()),
            combkey: bs58_encode(&tkm.1.to_bytes()),
        },
    };

    for (i, info) in cfg.keyset.iter_mut().enumerate() {
        match cli.mode {
            Mode::IncrementPort => {
                info.sailfish_url = cli
                    .sailfish_base_addr
                    .clone()
                    .with_port(cli.sailfish_base_addr.port() + i as u16);
                info.decrypt_url = cli
                    .decrypt_base_addr
                    .clone()
                    .with_port(cli.decrypt_base_addr.port() + i as u16);
                info.producer_url = cli
                    .producer_base_addr
                    .clone()
                    .with_port(cli.producer_base_addr.port() + i as u16);
            }
            Mode::IncrementAddress => {
                info.sailfish_url = incr_ip(&cli.sailfish_base_addr, i as u8)?;
                info.decrypt_url = incr_ip(&cli.decrypt_base_addr, i as u8)?;
                info.producer_url = incr_ip(&cli.producer_base_addr, i as u8)?;
            }
        }
    }

    serde_json::to_writer(io::stdout(), &cfg)?;

    Ok(())
}

fn mk_node_infos(dec: &TrustedKeyMaterial) -> impl Iterator<Item = NodeInfo> {
    iter::repeat_with(multisig::Keypair::generate)
        .zip(iter::repeat_with(|| x25519::Keypair::generate().unwrap()))
        .zip(&dec.2)
        .take(dec.2.len())
        .map(|((kp, xp), share)| NodeInfo {
            sailfish_url: (Ipv4Addr::LOCALHOST, 8000).into(),
            decrypt_url: (Ipv4Addr::LOCALHOST, 10000).into(),
            producer_url: (Ipv4Addr::LOCALHOST, 11000).into(),
            signing_key: kp.public_key(),
            dh_key: xp.public_key(),
            private: Some(PrivateKeys {
                sig: kp.secret_key(),
                dh: xp.secret_key(),
                dec: bs58_encode(&share.to_bytes()),
            }),
        })
}

fn incr_ip(addr: &Address, n: u8) -> Result<Address> {
    let Address::Inet(ip, port) = addr else {
        bail!("increment-address requires IP addresses")
    };
    let ip = match ip {
        IpAddr::V4(ip) => IpAddr::V4((u32::from(*ip) + u32::from(n)).into()),
        IpAddr::V6(ip) => IpAddr::V6((u128::from(*ip) + u128::from(n)).into()),
    };
    Ok(Address::Inet(ip, *port))
}
