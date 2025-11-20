use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use alloy::eips::BlockNumberOrTag;
use anyhow::Result;
use clap::Parser;
use cliquenet::Address;
use multisig::x25519;
use rand::SeedableRng;
use timeboost_config::{CommitteeMember, Espresso, Net, NodeConfig, NodeKeypair, NodeKeys};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// RNG seed for deterministic key generation.
    #[clap(long)]
    seed: Option<u64>,

    /// The base network address to bind to.
    #[clap(long, short)]
    bind: Address,

    /// The external network address to bind to.
    #[clap(long, short)]
    external: Option<Address>,

    /// The address of the Arbitrum Nitro node listener.
    #[clap(long)]
    nitro: Address,

    /// The public batch poster address.
    #[clap(long, short)]
    batchposter: Address,

    /// Espresso namespace ID.
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

    /// Where to write the config file to.
    #[clap(long, short)]
    output: Option<PathBuf>,
}

impl Args {
    fn mk_config(self) -> Result<()> {
        let mut s_rng = rand::rngs::StdRng::seed_from_u64(
            self.seed
                .map(|s| s.wrapping_pow(2))
                .unwrap_or_else(rand::random),
        );
        let mut d_rng = rand::rngs::StdRng::seed_from_u64(
            self.seed
                .map(|s| s.wrapping_pow(3))
                .unwrap_or_else(rand::random),
        );
        let mut p_rng = {
            use ark_std::rand::SeedableRng as _;
            ark_std::rand::rngs::StdRng::seed_from_u64(
                self.seed
                    .map(|s| s.wrapping_pow(4))
                    .unwrap_or_else(rand::random),
            )
        };

        let signing_keypair = multisig::Keypair::generate_with_rng(&mut s_rng);
        let dh_keypair = x25519::Keypair::generate_with_rng(&mut d_rng)?;
        let dkg_dec_key = DkgDecKey::rand(&mut p_rng);

        let config = NodeConfig {
            stamp: self
                .stamp_dir
                .join(format!("timeboost.{}.stamp", signing_keypair.public_key())),
            net: Net {
                bind: self.bind,
                nitro: self.nitro,
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
            espresso: Espresso {
                namespace: self.espresso_namespace,
                base_url: self.espresso_base_url,
                builder_base_url: self.espresso_builder_base_url,
                websockets_base_url: self.espresso_websocket_url,
                max_transaction_size: self.max_transaction_size,
            },
        };

        let member = CommitteeMember {
            address: self.external.unwrap_or_else(|| config.net.bind.clone()),
            signing_key: config.keys.signing.public,
            dh_key: config.keys.dh.public,
            dkg_enc_key: config.keys.dkg.public.clone(),
            batchposter: self.batchposter,
        };

        let node_toml = toml::to_string_pretty(&config)?;
        let member_toml = toml::to_string_pretty(&member)?;

        if let Some(path) = &self.output {
            let node_name = path.join(format!("{}.toml", signing_keypair.public_key()));
            let member_name = path.join(format!("{}.public.toml", signing_keypair.public_key()));
            let mut f = File::create(node_name)?;
            f.write_all(node_toml.as_bytes())?;
            let mut f = File::create(member_name)?;
            f.write_all(member_toml.as_bytes())?;
        } else {
            println!("{node_toml}");
            println!("###");
            println!("{member_toml}")
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    Args::parse().mk_config()
}
