use std::fs::{self, File};
use std::io::Write;
use std::net::IpAddr;
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::str::FromStr;

use alloy::consensus::crypto::secp256k1::public_key_to_address;
use alloy::eips::BlockNumberOrTag;
use alloy::signers::k256::ecdsa::VerifyingKey;
use anyhow::{Result, bail};
use ark_std::rand::SeedableRng as _;
use clap::{Parser, ValueEnum};
use cliquenet::Address;
use jiff::{SignedDuration, Timestamp};
use multisig::{CommitteeId, x25519};
use secp256k1::rand::SeedableRng as _;
use timeboost_config::{ChainConfig, GRPC_API_PORT_OFFSET, HTTP_API_PORT_OFFSET, Net, ParentChain};
use timeboost_config::{
    CommitteeConfig, CommitteeMember, Espresso, NodeConfig, NodeKeypair, NodeKeys,
};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use tracing::info;
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// How many nodes should configuration contain?
    #[clap(long, short)]
    num: NonZeroU8,

    /// Address modification mode for listen addresses.
    #[clap(long, default_value = "increment-port")]
    bind_mode: Mode,

    /// Address modification mode for public addresses.
    #[clap(long, default_value = "increment-port")]
    external_mode: Mode,

    /// Address modification mode for Nitro addresses.
    #[clap(long, default_value = "increment-port")]
    nitro_mode: Mode,

    /// RNG seed for deterministic key generation.
    #[clap(long)]
    seed: Option<u64>,

    #[clap(long)]
    committee_id: CommitteeId,

    /// The effective timestamp for this new committee.
    ///
    /// The timestamp format corresponds to RFC 3339, section 5.6, for example:
    /// 1970-01-01T18:00:00Z.
    #[clap(long)]
    timestamp: TimestampOrOffset,

    /// The base network address to bind to.
    ///
    /// Sailfish listens on this address. Other networks are relative to this address,
    /// listening at different ports.
    #[clap(long, short)]
    bind: Address,

    /// The public base network address.
    #[clap(long, short)]
    external_base: Option<Address>,

    /// HTTP API of a timeboost node.
    #[clap(long)]
    http_api: Option<Address>,

    /// Internal GRPC API of a timeboost node.
    #[clap(long)]
    grpc_api: Option<Address>,

    /// HTTP API of a batch poster node.
    #[clap(long)]
    batch_poster_api: Address,

    /// The address of the Arbitrum Nitro node listener where we forward inclusion list to.
    #[clap(long)]
    nitro: Option<Address>,

    #[clap(long)]
    chain_namespace: u64,

    /// Parent chain rpc url
    #[clap(long)]
    parent_rpc_url: Url,

    /// Parent chain websocket url
    #[clap(long)]
    parent_ws_url: Url,

    /// Parent chain id
    #[clap(long)]
    parent_chain_id: u64,

    /// Parent chain inbox contract address
    #[clap(long)]
    parent_ibox_contract: alloy::primitives::Address,

    /// Contract address of the deployed KeyManager (or its proxy if upgradable)
    /// You should get this info from `init_chain()` in test.
    #[clap(long)]
    key_manager_contract: alloy::primitives::Address,

    /// Parent chain inbox block tag
    #[clap(long, default_value = "finalized")]
    parent_block_tag: BlockNumberOrTag,

    /// Base URL of Espresso's REST API.
    #[clap(
        long,
        default_value = "https://query.decaf.testnet.espresso.network/v1/"
    )]
    espresso_base_url: Url,

    /// Builder base URL of Espresso's REST API.
    #[clap(long)]
    espresso_builder_base_url: Option<Url>,

    /// Base URL of Espresso's Websocket API.
    #[clap(long, default_value = "wss://query.decaf.testnet.espresso.network/v1/")]
    espresso_websocket_url: Url,

    #[clap(long, default_value_t = 1024 * 1024)]
    max_transaction_size: usize,

    /// Directory to store timeboost stamp file in.
    #[clap(long, short)]
    stamp_dir: PathBuf,

    /// The directory to stored all generated `NodeConfig` files for all committee members
    #[clap(long, short)]
    output: PathBuf,
}

#[derive(Debug, Clone)]
struct TimestampOrOffset(Timestamp);

impl FromStr for TimestampOrOffset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ts) = Timestamp::from_str(s) {
            Ok(Self(ts))
        } else if let Ok(dur) = s.parse::<SignedDuration>() {
            Ok(Self(Timestamp::now() + dur))
        } else {
            Err("Expected RFC3339 timestamp or [+/-]duration".into())
        }
    }
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

        let mut committee_config_file = File::create(self.output.join("committee.toml"))?;
        let mut members = vec![];

        for i in 0..self.num.get() {
            let signing_keypair = multisig::Keypair::generate_with_rng(&mut s_rng);
            let dh_keypair = x25519::Keypair::generate_with_rng(&mut d_rng)?;
            let dkg_dec_key = DkgDecKey::rand(&mut p_rng);
            let bind_addr = self.bind_mode.adjust_addr(i, &self.bind)?;
            let batch_poster_api = self.bind_mode.adjust_addr(i, &self.batch_poster_api)?;
            let pub_addr = self
                .external_base
                .as_ref()
                .map(|a| self.external_mode.adjust_addr(i, a))
                .transpose()?;
            let http_addr = self
                .http_api
                .as_ref()
                .map(|a| self.external_mode.adjust_addr(i, a))
                .transpose()?;
            let inter_addr = self
                .grpc_api
                .as_ref()
                .map(|a| self.external_mode.adjust_addr(i, a))
                .transpose()?;
            let nitro_addr = self
                .nitro
                .as_ref()
                .map(|a| self.nitro_mode.adjust_addr(i, a))
                .transpose()?;
            let config = NodeConfig {
                committee: self.committee_id,
                stamp: self.stamp_dir.join(format!("timeboost.{i}.stamp")),
                net: Net {
                    bind: bind_addr.clone(),
                    batch_poster_api: batch_poster_api.clone(),
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
                    namespace: self.chain_namespace,
                    parent: ParentChain {
                        id: self.parent_chain_id,
                        rpc_url: self.parent_rpc_url.clone(),
                        ws_url: self.parent_ws_url.clone(),
                        ibox_contract: self.parent_ibox_contract,
                        block_tag: self.parent_block_tag,
                        key_manager_contract: self.key_manager_contract,
                    },
                },
                espresso: Espresso {
                    base_url: self.espresso_base_url.clone(),
                    builder_base_url: self.espresso_builder_base_url.clone(),
                    websockets_base_url: self.espresso_websocket_url.clone(),
                    max_transaction_size: self.max_transaction_size,
                },
            };

            let pub_key = VerifyingKey::from_sec1_bytes(&config.keys.signing.public.to_bytes())?;

            members.push(CommitteeMember {
                node: format!("node_{i}"),
                signing_key: config.keys.signing.public,
                dh_key: config.keys.dh.public,
                dkg_enc_key: config.keys.dkg.public.clone(),
                batch_poster_api: batch_poster_api.clone(),
                address: pub_addr.clone().unwrap_or_else(|| bind_addr.clone()),
                http_api: http_addr
                    .or_else(|| {
                        pub_addr
                            .clone()
                            .map(|a| a.with_offset(HTTP_API_PORT_OFFSET))
                    })
                    .unwrap_or_else(|| bind_addr.clone().with_offset(HTTP_API_PORT_OFFSET)),
                grpc_api: inter_addr
                    .or_else(|| {
                        pub_addr
                            .clone()
                            .map(|a| a.with_offset(GRPC_API_PORT_OFFSET))
                    })
                    .unwrap_or_else(|| bind_addr.clone().with_offset(GRPC_API_PORT_OFFSET)),
                sig_key_address: public_key_to_address(pub_key),
            });

            let mut node_config_file = File::create(self.output.join(format!("node_{i}.toml")))?;
            node_config_file.write_all(toml::to_string_pretty(&config)?.as_bytes())?;
        }

        let committee_config = CommitteeConfig {
            id: self.committee_id,
            effective_timestamp: self.timestamp.0,
            members,
        };
        committee_config_file.write_all(toml::to_string_pretty(&committee_config)?.as_bytes())?;

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    args.mk_config()?;

    info!("successfully produced configuration");
    Ok(())
}
