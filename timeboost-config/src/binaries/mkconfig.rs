use std::fs::{self, File};
use std::io::Write;
use std::net::IpAddr;
use std::num::NonZeroU8;
use std::path::PathBuf;

use alloy::eips::BlockNumberOrTag;
use anyhow::{Result, bail};
use ark_std::rand::SeedableRng as _;
use clap::{Parser, ValueEnum};
use cliquenet::Address;
use multisig::x25519;
use secp256k1::rand::SeedableRng as _;
use timeboost_config::{ChainConfig, Espresso, Net, NodeConfig, NodeKeypair, NodeKeys};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// How many nodes should configuration contain?
    #[clap(long, short)]
    num: NonZeroU8,

    /// RNG seed for deterministic key generation.
    #[clap(long)]
    seed: Option<u64>,

    /// Address modification mode for listen addresses.
    #[clap(long, default_value = "increment-port")]
    bind_mode: Mode,

    /// Address modification mode for Nitro addresses.
    #[clap(long, default_value = "increment-port")]
    nitro_mode: Mode,

    /// The base network address to bind to.
    ///
    /// Sailfish listens on this address. Other networks are relative to this address,
    /// listening at different ports.
    #[clap(long, short)]
    bind: Address,

    /// The address of the Arbitrum Nitro node listener where we forward inclusion list to.
    #[clap(long)]
    nitro: Option<Address>,

    /// Parent chain rpc url
    #[clap(long)]
    chain_rpc_url: Url,

    /// Parent chain id
    #[clap(long)]
    chain_id: u64,

    /// Parent chain inbox contract address
    #[clap(long)]
    inbox_contract: alloy::primitives::Address,

    /// Parent chain inbox block tag
    #[clap(long, default_value = "finalized")]
    inbox_block_tag: BlockNumberOrTag,

    #[clap(long)]
    espresso_namespace: u64,

    /// Base URL of Espresso's REST API.
    #[clap(long)]
    espresso_base_url: Url,

    /// Base URL of Espresso's Websocket API.
    #[clap(long)]
    espresso_websocket_url: Url,

    /// Builder base URL of Espresso's REST API.
    #[clap(long)]
    espresso_builder_base_url: Option<Url>,

    #[clap(long, default_value_t = 1024 * 1024)]
    max_transaction_size: usize,

    /// Directory to store timeboost stamp file in.
    #[clap(long, short)]
    stamp_dir: PathBuf,

    /// The directory to stored all generated `NodeConfig` files for all committee members
    #[clap(long, short)]
    output: PathBuf,
}

/// How should addresses be updated?
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// Leave the address unchanged.
    Unchanged,
    /// Increment the port number of addresses.
    IncrementPort,
    /// Increment the IP address.
    IncrementAddress,
    /// Trailing number on DNS name.
    DockerDns,
}

impl Mode {
    fn adjust_addr(&self, i: u8, base: &Address) -> Result<Address> {
        match self {
            Mode::Unchanged => Ok(base.clone()),
            Mode::IncrementPort => Ok(base.clone().with_port(base.port() + 10 * u16::from(i))),
            Mode::IncrementAddress => {
                let Address::Inet(ip, port) = base else {
                    bail!("increment-address requires IP addresses")
                };
                let ip = match ip {
                    IpAddr::V4(ip) => IpAddr::V4((u32::from(*ip) + u32::from(i)).into()),
                    IpAddr::V6(ip) => IpAddr::V6((u128::from(*ip) + u128::from(i)).into()),
                };
                Ok(Address::Inet(ip, *port))
            }
            Mode::DockerDns => {
                let Address::Name(name, port) = base else {
                    bail!("increment dns requires dns name")
                };
                if name.contains("host.docker") {
                    return Ok(Address::Name(name.to_string(), *port + (i as u16 * 10)));
                } else if let Some(index) = name.find('.') {
                    let (first, rest) = name.split_at(index);
                    return Ok(Address::Name(format!("{}{}{}", first, i, rest), *port));
                }
                Ok(Address::Name(format!("{}{}", name, i), *port))
            }
        }
    }
}

impl Args {
    fn mk_config(&self) -> Result<()> {
        let mut s_rng = secp256k1::rand::rngs::StdRng::seed_from_u64(
            self.seed
                .map(|s| s.wrapping_pow(2))
                .unwrap_or_else(rand::random),
        );
        let mut d_rng = secp256k1::rand::rngs::StdRng::seed_from_u64(
            self.seed
                .map(|s| s.wrapping_pow(3))
                .unwrap_or_else(rand::random),
        );
        let mut p_rng = ark_std::rand::rngs::StdRng::seed_from_u64(
            self.seed
                .map(|s| s.wrapping_pow(4))
                .unwrap_or_else(rand::random),
        );

        fs::create_dir_all(&self.output).expect("create output dir should succeed");
        if !self.output.is_dir() {
            bail!("--output only accepts valid directory path");
        }

        for i in 0..self.num.get() {
            let signing_keypair = multisig::Keypair::generate_with_rng(&mut s_rng);
            let dh_keypair = x25519::Keypair::generate_with_rng(&mut d_rng)?;
            let dkg_dec_key = DkgDecKey::rand(&mut p_rng);
            let bind_addr = self.bind_mode.adjust_addr(i, &self.bind)?;
            let nitro_addr = self
                .nitro
                .as_ref()
                .map(|a| self.nitro_mode.adjust_addr(i, a))
                .transpose()?;
            let config = NodeConfig {
                stamp: self
                    .stamp_dir
                    .join(format!("timeboost.{}.stamp", signing_keypair.public_key())),
                net: Net {
                    bind: bind_addr.clone(),
                    nitro: nitro_addr,
                },
                keys: NodeKeys {
                    signing: NodeKeypair {
                        secret: signing_keypair.secret_key(),
                        public: signing_keypair.public_key(),
                    },
                    dh: NodeKeypair {
                        secret: dh_keypair.secret_key(),
                        public: dh_keypair.public_key(),
                    },
                    dkg: NodeKeypair {
                        secret: dkg_dec_key.clone(),
                        public: DkgEncKey::from(&dkg_dec_key),
                    },
                },
                chain: ChainConfig {
                    id: self.chain_id,
                    rpc_url: self.chain_rpc_url.clone(),
                    inbox_contract: self.inbox_contract,
                    inbox_block_tag: self.inbox_block_tag,
                },
                espresso: Espresso {
                    namespace: self.espresso_namespace,
                    base_url: self.espresso_base_url.clone(),
                    builder_base_url: self.espresso_builder_base_url.clone(),
                    websockets_base_url: self.espresso_websocket_url.clone(),
                    max_transaction_size: self.max_transaction_size,
                },
            };

            let mut node_config_file = File::create(
                self.output
                    .join(format!("{}.toml", signing_keypair.public_key())),
            )?;
            node_config_file.write_all(toml::to_string_pretty(&config)?.as_bytes())?;
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    args.mk_config()?;

    Ok(())
}
