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
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use timeboost_types::{ChainConfig, ParentChain};
use timeboost_utils::keyset::{
    CommitteeConfig, CommitteeMember, InternalNet, NodeConfig, NodeKeyConfig, NodeKeypairConfig,
    NodeNetConfig, PublicNet,
};
use timeboost_utils::types::logging;
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// How many nodes should configuration contain?
    #[clap(long, short)]
    num: NonZeroU8,

    /// Address modification mode.
    #[clap(long, short, default_value = "increment-port")]
    mode: Mode,

    /// RNG seed for deterministic key generation
    #[clap(long)]
    seed: Option<u64>,

    /// The effective timestamp for this new committee
    #[clap(long)]
    timestamp: jiff::Timestamp,

    /// The sailfish network address. Decrypter, certifier, and internal address are derived:
    /// sharing the same IP as the sailfish IP, and a different (but fixed) port number.
    #[clap(long, short)]
    public_addr: Address,

    /// Internal gPRC endpoints among nodes, default to same IP as sailfish with port + 3000
    #[clap(long)]
    internal_addr: Address,

    /// The address of the Arbitrum Nitro node listener where we forward inclusion list to.
    #[clap(long)]
    nitro_addr: Option<Address>,

    #[clap(long)]
    chain_namespace: u64,

    /// Parent chain rpc url
    #[clap(long)]
    parent_rpc_url: Url,

    /// Parent chain id
    #[clap(long)]
    parent_chain_id: u64,

    /// Parent chain inbox contract adddress
    #[clap(long)]
    parent_ibox_contract: alloy::primitives::Address,

    /// Contract address of the deployed KeyManager (or its proxy if upgradable)
    /// You should get this info from `init_chain()` in test.
    #[clap(long)]
    key_manager_contract: alloy::primitives::Address,

    /// Parent chain inbox block tag
    #[clap(long, default_value = "finalized")]
    parent_block_tag: BlockNumberOrTag,

    /// The directory to stored all generated `NodeConfig` files for all committee members
    #[clap(long, short)]
    output: PathBuf,
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
            let dh_keypair = x25519::Keypair::generate_with_rng(&mut d_rng).unwrap();
            let dkg_dec_key = DkgDecKey::rand(&mut p_rng);

            let public_addr = self.adjust_addr(i, &self.public_addr)?;
            let internal_addr = self.adjust_addr(i, &self.internal_addr)?;
            let nitro_addr = if let Some(addr) = &self.nitro_addr {
                Some(self.adjust_addr(i, addr)?)
            } else {
                None
            };

            let config = NodeConfig {
                net: NodeNetConfig {
                    public: PublicNet {
                        address: public_addr,
                    },
                    internal: InternalNet {
                        address: internal_addr,
                        nitro: nitro_addr,
                    },
                },
                keys: NodeKeyConfig {
                    signing: NodeKeypairConfig {
                        secret: signing_keypair.secret_key(),
                        public: signing_keypair.public_key(),
                    },
                    dh: NodeKeypairConfig {
                        secret: dh_keypair.secret_key(),
                        public: dh_keypair.public_key(),
                    },
                    dkg: NodeKeypairConfig {
                        secret: dkg_dec_key.clone(),
                        public: DkgEncKey::from(&dkg_dec_key),
                    },
                },
                chain: ChainConfig::builder()
                    .namespace(self.chain_namespace)
                    .parent(
                        ParentChain::builder()
                            .id(self.parent_chain_id)
                            .rpc_url(self.parent_rpc_url.clone())
                            .ibox_contract(self.parent_ibox_contract)
                            .key_manager_contract(self.key_manager_contract)
                            .block_tag(self.parent_block_tag)
                            .build(),
                    )
                    .build(),
            };

            members.push(CommitteeMember {
                signing_key: config.keys.signing.public,
                dh_key: config.keys.dh.public,
                dkg_enc_key: config.keys.dkg.public.clone(),
                public_address: config.net.public.address.clone(),
            });

            let mut node_config_file = File::create(self.output.join(format!("node_{i}.toml")))?;
            node_config_file.write_all(toml::to_string_pretty(&config)?.as_bytes())?;
        }

        let committee_config = CommitteeConfig {
            effective_timestamp: self.timestamp,
            members,
        };
        committee_config_file.write_all(toml::to_string_pretty(&committee_config)?.as_bytes())?;

        Ok(())
    }

    fn adjust_addr(&self, i: u8, base: &Address) -> Result<Address> {
        match self.mode {
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
        }
    }
}

fn main() -> Result<()> {
    logging::init_logging();

    let args = Args::parse();
    args.mk_config()?;

    Ok(())
}
