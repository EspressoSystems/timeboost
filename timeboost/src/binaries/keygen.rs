//! Utility program to generate keypairs

use alloy::hex;
use anyhow::anyhow;
use clap::{Parser, ValueEnum};
use rand::Rng;
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};
use timeboost_crypto::DecryptionScheme;
use timeboost_utils::{bs58_encode, sig_keypair_from_seed_indexed, types::logging};
use tracing::{debug, info};

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
                    let path = out.join(format!("{index}.env"));
                    let mut env_file = File::options().append(true).create(true).open(&path)?;
                    let keypair = sig_keypair_from_seed_indexed(seed, index as u64);
                    let privkey = bs58_encode(&keypair.secret_key().as_bytes());
                    let pubkey = bs58_encode(&keypair.public_key().as_bytes());
                    writeln!(env_file, "TIMEBOOST_SIGNATURE_KEY={}", pubkey)?;
                    writeln!(env_file, "TIMEBOOST_PRIVATE_SIGNATURE_KEY={}", privkey)?;
                    info!("generated signature keypair: {}", pubkey);
                    debug!("private signature key written to {}", path.display());
                }
            }
            Self::Decryption => {
                let (pub_key, comb_key, key_shares) = DecryptionScheme::trusted_keygen(num as u16);
                debug!("generating new threshold encryption keyset");
                let pub_key = bs58_encode(&pub_key.as_bytes());
                let comb_key = bs58_encode(&comb_key.as_bytes());

                for index in 0..num {
                    let key_share = key_shares
                        .get(index)
                        .expect("key share should exist in generated material");
                    let key_share = bs58_encode(&key_share.as_bytes());
                    let path = out.join(format!("{index}.env"));
                    let mut env_file = File::options().append(true).create(true).open(&path)?;
                    writeln!(env_file, "TIMEBOOST_PRIVATE_DECRYPTION_KEY={}", key_share)?;
                    writeln!(env_file, "TIMEBOOST_ENCRYPTION_KEY={}", pub_key)?;
                    writeln!(env_file, "TIMEBOOST_COMBINATION_KEY={}", comb_key)?;
                    debug!("private decryption key written to {}", path.display());
                }
                info!("generated threshold encryption keyset with:\nTIMEBOOST_ENCRYPTION_KEY={}\nTIMEBOOST_COMBINATION_KEY={}",
                      pub_key, comb_key);
            }
        }
        Ok(())
    }
}

/// Utility program for generating keys
///
/// With no options, this program generates the keys needed for a committee of 5 Timeboost nodes.
/// Options can be given to control the number or type of keys generated.
///
/// Note that signature keys can be generated independently of other keys but
/// decryption keys of a committee can only be derived from the same trusted setup.
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

    /// Cryptographic scheme subject to key generation.
    ///
    /// Timeboost nodes require both a signature key and a decryption key share.
    /// By default, this program generates these keys in pairs, to make it easy to
    /// configure Timeboost nodes, but this option can be specified to generate keys
    /// for only one of the schemes.
    #[clap(long, default_value = "all")]
    scheme: Scheme,

    /// Size of the committee to generate keys for.
    ///
    /// Default is 5.
    #[clap(long, short = 'n', name = "N", default_value = "5")]
    num: usize,

    /// Write private keys to .env files under DIR.
    ///
    /// DIR must be a directory. If it does not exist, one will be created. Private keys will
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
    debug!(
        "Generating {} keypairs for {:?} scheme",
        cli.num, cli.scheme
    );

    // Create output dir if necessary.
    fs::create_dir_all(&cli.out)?;

    let seed = cli.seed.unwrap_or_else(|| {
        debug!("No seed provided, generating a random seed");
        gen_default_seed()
    });
    let out = cli.out;
    let mut env_file = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out.join(".seed"))?;
    writeln!(env_file, "TIMEBOOST_SIGNATURE_SEED={}", hex::encode(seed))?;
    let _ = cli.scheme.gen(seed, cli.num, &out);

    Ok(())
}
