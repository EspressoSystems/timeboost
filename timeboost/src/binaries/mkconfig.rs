use std::fs;
use std::path::PathBuf;

use alloy::eips::BlockNumberOrTag;
use anyhow::Result;
use ark_std::rand::SeedableRng as _;
use clap::Parser;
use cliquenet::Address;
use multisig::x25519;
use secp256k1::rand::SeedableRng as _;
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use timeboost_types::ChainConfig;
use timeboost_utils::Blackbox;
use timeboost_utils::keyset::{
    CommitteeConfig, CommitteeMember, NodeConfig, NodeEncodedKeypairConfig, NodeKeyConfig,
    NodeKeypairConfig, NodeNetConfig,
};
use timeboost_utils::types::logging;
use url::Url;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// The sailfish network address. Decrypter, certifier, and internal address are derived:
    /// sharing the same IP as the sailfish IP, and a different (but fixed) port number.
    #[clap(long, short)]
    sailfish: Address,

    /// RNG seed for deterministic key generation
    #[clap(long)]
    seed: Option<u64>,

    /// Internal gPRC endpoints among nodes, default to same IP as sailfish with port + 3000
    #[clap(long)]
    internal_addr: Option<Address>,

    /// The address of the Arbitrum Nitro node listener where we forward inclusion list to.
    #[clap(long)]
    nitro_addr: Option<Address>,

    /// Contract address of the deployed KeyManager (or its proxy if upgradable)
    /// You should get this info from `init_chain()` in test.
    #[clap(long)]
    key_manager_addr: alloy::primitives::Address,

    /// Parent chain rpc url
    #[clap(long)]
    parent_rpc_url: Url,

    /// Parent chain id
    #[clap(long)]
    parent_chain_id: u64,

    /// Parent chain inbox contract adddress
    #[clap(long)]
    parent_ibox_contr_addr: alloy::primitives::Address,

    /// Parent chain inbox block tag
    #[clap(long, default_value = "finalized")]
    parent_block_tag: BlockNumberOrTag,

    /// Path to stored the generated `NodeConfig`, if None, print to stdout
    #[clap(long, short)]
    output: Option<PathBuf>,
}

impl Args {
    fn mk_config(&self) -> Result<NodeConfig> {
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

        // Generate multisig keypair
        let signing_keypair = multisig::Keypair::generate_with_rng(&mut s_rng);
        // Generate x25519 keypair
        let dh_keypair = x25519::Keypair::generate_with_rng(&mut d_rng).unwrap();
        // Generate DKG keypair for this node using p_rng
        let dkg_dec_key = DkgDecKey::rand(&mut p_rng);

        let config = NodeConfig {
            net: NodeNetConfig::new(
                self.sailfish.clone(),
                self.internal_addr.clone(),
                self.nitro_addr.clone(),
            ),
            keys: NodeKeyConfig {
                signing: NodeKeypairConfig {
                    secret: signing_keypair.secret_key(),
                    public: signing_keypair.public_key(),
                },
                dh: NodeKeypairConfig {
                    secret: dh_keypair.secret_key(),
                    public: dh_keypair.public_key(),
                },
                dkg: NodeEncodedKeypairConfig {
                    secret: Blackbox::encode(dkg_dec_key.clone())?,
                    public: Blackbox::encode(DkgEncKey::from(&dkg_dec_key))?,
                },
            },
            chain_config: ChainConfig::new(
                self.parent_chain_id,
                self.parent_rpc_url.clone(),
                self.parent_ibox_contr_addr,
                self.parent_block_tag,
                self.key_manager_addr,
            ),
        };

        Ok(config)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    logging::init_logging();

    let cfg = args.mk_config()?;
    let toml = toml::to_string_pretty(&cfg)?;

    if let Some(out) = &args.output {
        // first write the per node config
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out, &toml)?;

        // second append this node's public info to a centralized committee.toml
        // for key manager to register them in the contract
        let committee_file = out.with_file_name("committee.toml");
        let mut committee_config: CommitteeConfig = if committee_file.exists() {
            toml::from_str(&fs::read_to_string(&committee_file)?)?
        } else {
            CommitteeConfig {
                effective_timestamp: 1756181061.into(),
                members: Vec::new(),
            }
        };

        let new_member = CommitteeMember {
            signing_key: cfg.keys.signing.public,
            dh_key: cfg.keys.dh.public,
            dkg_enc_key: cfg.keys.dkg.public.clone(),
            sailfish_address: cfg.net.sailfish.clone(),
        };
        if !committee_config.members.contains(&new_member) {
            committee_config.members.push(new_member);
        }

        fs::write(committee_file, toml::to_string_pretty(&committee_config)?)?;
    } else {
        println!("{toml}");
    }

    Ok(())
}
