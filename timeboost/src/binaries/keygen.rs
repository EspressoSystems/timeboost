//! Utility program to generate keypairs

use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use anyhow::anyhow;
use clap::{Parser, ValueEnum};

use alloy::hex;

use rand::Rng;
use timeboost_crypto::{sg_encryption::KeyShare, G};
use timeboost_utils::{sig_keypair_from_seed_indexed, thres_enc_keygen, types::logging};
use tracing::info_span;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Scheme {
    #[default]
    All,
    Signature,
    Decryption,
}

impl Scheme {
    fn gen(self, seed: [u8; 32], num: usize, out: &PathBuf) -> anyhow::Result<()> {
        match self {
            Self::All => {
                Self::Signature.gen(seed, num, out)?;
                Self::Decryption.gen(seed, num, out)?;
            }
            Self::Signature => {
                for index in 0..num {
                    let span = info_span!("gen", index);
                    let _enter = span.enter();
                    tracing::info!("generating new signature key pair");

                    let path = out.join(format!("{index}.env"));
                    let mut env_file = File::options()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&path)?;
                    let keypair = sig_keypair_from_seed_indexed(seed, index as u64);
                    let priv_key_bytes = keypair.secret_key().as_bytes();
                    let pub_key_bytes = keypair.public_key().as_bytes();
                    writeln!(
                        env_file,
                        "TIMEBOOST_PUBLIC_SIGNATURE_KEY={}",
                        bs58::encode(&pub_key_bytes).into_string()
                    )?;
                    writeln!(
                        env_file,
                        "TIMEBOOST_PRIVATE_SIGNATURE_KEY={}",
                        bs58::encode(&priv_key_bytes).into_string()
                    )?;
                    tracing::info!(
                        "generated signature keypair: {}",
                        bs58::encode(&pub_key_bytes).into_string()
                    );

                    tracing::info!("private signature key written to {}", path.display());
                }
            }
            Self::Decryption => {
                let (pub_key, comb_key, key_shares) = thres_enc_keygen(num as u32);
                tracing::info!("generating new threshold encryption keyset");
                let pub_key = bs58::encode(bincode::serialize(&pub_key)?).into_string();
                let comb_key = bs58::encode(bincode::serialize(&comb_key)?).into_string();

                for index in 0..num {
                    let span = info_span!("gen", index);
                    let _enter = span.enter();
                    let key_share = bs58::encode(bincode::serialize::<KeyShare<G>>(
                        key_shares.get(index).unwrap(),
                    )?)
                    .into_string();
                    let path = out.join(format!("{index}.env"));
                    let mut env_file = File::options()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&path)?;
                    writeln!(env_file, "TIMEBOOST_ENCRYPTION_KEY={}", pub_key)?;
                    writeln!(env_file, "TIMEBOOST_COMBINATION_KEY={}", comb_key)?;
                    writeln!(env_file, "TIMEBOOST_PRIVATE_DECRYPTION_KEY={}", key_share)?;
                    tracing::info!("private decryption key written to {}", path.display());
                }
                tracing::info!(
                    "generated threshold encryption keyset with encryption key: {} and comb_key: {}",
                    pub_key,
                    comb_key
                );
            }
        }
        Ok(())
    }
}

/// Utility program to generate keys
///
/// With no options, this program generates the keys needed to run a single Timeboost node.
/// Options can be given to control the number or type of keys generated.
///
/// Generated secret keys are written to a file in .env format, which can directly be used to
/// configure a Timeboost node. Public information about the generated keys is printed to stdout.
#[derive(Clone, Debug, Parser)]
struct Cli {
    /// Seed for generating keys.
    ///
    /// If not provided, a random seed will be generated using system entropy.
    #[clap(long, short = 's', value_parser = parse_seed)]
    seed: Option<[u8; 32]>,

    /// Signature scheme to generate.
    ///
    /// Sequencer nodes require both a BLS key (called the staking key) and a Schnorr key (called
    /// the state key). By default, this program generates these keys in pairs, to make it easy to
    /// configure sequencer nodes, but this option can be specified to generate keys for only one of
    /// the signature schemes.
    #[clap(long, default_value = "all")]
    scheme: Scheme,

    /// Number of setups to generate.
    ///
    /// Default is 1.
    #[clap(long, short = 'n', name = "N", default_value = "1")]
    num: usize,

    /// Write private keys to .env files under DIR.
    ///
    /// DIR must be a directory. If it does not exist, one will be created. Private key setups will
    /// be written to files immediately under DIR, with names like 0.env, 1.env, etc. for 0 through
    /// N - 1. The random seed used to generate the keys will also be written to a file in DIR
    /// called .seed.
    #[clap(short, long, name = "OUT")]
    out: PathBuf,
}

fn parse_seed(s: &str) -> Result<[u8; 32], anyhow::Error> {
    let bytes = hex::decode(s)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("invalid seed length: {} (expected 32)", bytes.len()))
}

fn gen_default_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    let mut rng = rand::rngs::ThreadRng::default();
    rng.fill(&mut seed);

    seed
}

fn main() -> anyhow::Result<()> {
    logging::init_logging();

    let cli = Cli::parse();
    tracing::debug!(
        "Generating {} keypairs for {:?} scheme",
        cli.num,
        cli.scheme
    );

    // Create output dir if necessary.
    fs::create_dir_all(&cli.out)?;

    let seed = cli.seed.unwrap_or_else(|| {
        tracing::debug!("No seed provided, generating a random seed");
        gen_default_seed()
    });
    let out = cli.out;
    fs::write(out.join(".seed"), hex::encode(seed))?;
    let _ = cli.scheme.gen(seed, cli.num, &out);

    Ok(())
}
