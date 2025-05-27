use std::net::IpAddr;
use std::num::NonZeroU8;
use std::{io, iter};

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use cliquenet::Address;
use multisig::x25519;
use timeboost_crypto::{DecryptionScheme, TrustedKeyMaterial};
use timeboost_utils::keyset::{KeysetConfig, NodeInfo, PrivateKeys, PublicDecInfo};
use timeboost_utils::types::logging;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// How many nodes should configuration contain?
    #[clap(long, short)]
    num: NonZeroU8,

    /// The first sailfish address.
    #[clap(long, short)]
    sailfish_base_addr: Address,

    /// The first decrypter address.
    #[clap(long, short)]
    decrypt_base_addr: Address,

    /// The first producer address.
    #[clap(long, short)]
    producer_base_addr: Address,

    /// Address modification mode.
    #[clap(long, short, default_value = "increment-port")]
    mode: Mode,
}

/// How should addresses be updated?
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Mode {
    /// Increment the port number of addresses.
    #[default]
    IncrementPort,
    /// Increment the IP address.
    IncrementAddress,
}

impl Args {
    fn mk_node_infos(&self, dec: &TrustedKeyMaterial) -> impl Iterator<Item = Result<NodeInfo>> {
        iter::repeat_with(multisig::Keypair::generate)
            .zip(iter::repeat_with(|| x25519::Keypair::generate().unwrap()))
            .zip(&dec.2)
            .enumerate()
            .take(dec.2.len())
            .map(|(i, ((kp, xp), share))| {
                let i = i as u8;
                Ok(NodeInfo {
                    sailfish_address: self.adjust_addr(i, &self.sailfish_base_addr)?,
                    decrypt_address: self.adjust_addr(i, &self.decrypt_base_addr)?,
                    producer_address: self.adjust_addr(i, &self.producer_base_addr)?,
                    signing_key: kp.public_key(),
                    dh_key: xp.public_key(),
                    private: Some(PrivateKeys {
                        signing_key: kp.secret_key(),
                        dh_key: xp.secret_key(),
                        dec_share: share.clone(),
                    }),
                })
            })
    }

    fn adjust_addr(&self, i: u8, a: &Address) -> Result<Address> {
        match self.mode {
            Mode::IncrementPort => Ok(a.clone().with_port(a.port() + u16::from(i))),
            Mode::IncrementAddress => {
                let Address::Inet(ip, port) = a else {
                    bail!("increment-address requires IP addresses")
                };
                let ip = match ip {
                    IpAddr::V4(ip) => IpAddr::V4((u32::from(*ip) + u32::from(i)).into()),
                    IpAddr::V6(ip) => IpAddr::V6((u128::from(*ip) + u128::from(i)).into()),
                };
                Ok(Address::Inet(ip, *port))
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    logging::init_logging();

    let tkm = DecryptionScheme::trusted_keygen(args.num.into());
    let cfg = KeysetConfig {
        keyset: args.mk_node_infos(&tkm).collect::<Result<_>>()?,
        dec_keyset: PublicDecInfo {
            pubkey: tkm.0.clone(),
            combkey: tkm.1.clone(),
        },
    };
    serde_json::to_writer(io::stdout(), &cfg)?;

    Ok(())
}
