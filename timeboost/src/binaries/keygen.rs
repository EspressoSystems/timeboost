//! Utility program to generate keypairs

use alloy_primitives::hex;
use anyhow::anyhow;
use ark_std::rand::SeedableRng;
use clap::{Parser, ValueEnum};
use rand::Rng;
use std::{
    fs::{self, File},
    io::Write,
    num::NonZeroUsize,
    path::PathBuf,
};
use timeboost_crypto::DecryptionScheme;
use timeboost_utils::{bs58_encode, types::logging};
use timeboost_utils::{dh_keypair_from_seed_indexed, sig_keypair_from_seed_indexed};
use tracing::{debug, info};

/// Test config files whose key materials should be updated
const TEST_CONFIG_FILES: [&str; 4] = [
    "local.json",
    "docker.json",
    "cloud_single.json",
    "cloud_multi.json",
];

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Scheme {
    #[default]
    All,
    Signature,
    DH,
    Decryption,
}

impl Scheme {
    fn generate(
        self,
        seed: [u8; 32],
        num: NonZeroUsize,
        out: Option<PathBuf>,
    ) -> anyhow::Result<()> {
        match self {
            Self::All => {
                Self::Signature.generate(seed, num, out.clone())?;
                Self::DH.generate(seed, num, out.clone())?;
                Self::Decryption.generate(seed, num, out.clone())?;
            }
            Self::Signature => {
                let keypairs = (0..num.into())
                    .map(|idx| sig_keypair_from_seed_indexed(seed, idx as u64))
                    .collect::<Vec<_>>();

                if let Some(out) = out {
                    for (idx, keypair) in keypairs.iter().enumerate() {
                        let path = out.join(format!("{idx}.env"));
                        let mut env_file = File::options().append(true).create(true).open(&path)?;
                        let privkey = bs58_encode(&keypair.secret_key().as_bytes());
                        let pubkey = bs58_encode(&keypair.public_key().to_bytes());
                        writeln!(env_file, "TIMEBOOST_SIGNATURE_KEY={}", pubkey)?;
                        writeln!(env_file, "TIMEBOOST_PRIVATE_SIGNATURE_KEY={}", privkey)?;
                        info!("generated signature keypair: {}", pubkey);
                        debug!("private signature key written to {}", path.display());
                    }
                } else {
                    for f in TEST_CONFIG_FILES {
                        let path = PathBuf::from("test-configs").join(f);
                        debug!(
                            "updating {} with new signature keys",
                            path.to_str().unwrap()
                        );
                        todo!("blocked by https://github.com/EspressoSystems/timeboost/issues/355");
                    }
                }
            }
            Self::DH => {
                for index in 0..num.into() {
                    // TODO(alex): unify this with other branches
                    let path = out.clone().unwrap().join(format!("{index}.env"));
                    let mut env_file = File::options().append(true).create(true).open(&path)?;
                    let keypair = dh_keypair_from_seed_indexed(seed, index as u64);
                    let privkey = bs58_encode(&keypair.secret_key().as_bytes());
                    let pubkey = bs58_encode(&keypair.public_key().as_bytes());
                    writeln!(env_file, "TIMEBOOST_DH_KEY={}", pubkey)?;
                    writeln!(env_file, "TIMEBOOST_PRIVATE_DH_KEY={}", privkey)?;
                    info!("generated dh keypair: {}", pubkey);
                    debug!("private dh key written to {}", path.display());
                }
            }
            Self::Decryption => {
                let mut rng = ark_std::rand::rngs::StdRng::from_seed(seed);
                let (pub_key, comb_key, key_shares) =
                    DecryptionScheme::trusted_keygen_with_rng(num, &mut rng);
                debug!("generating new threshold encryption keyset");

                if let Some(out) = out {
                    let pub_key = bs58_encode(&pub_key.to_bytes());
                    let comb_key = bs58_encode(&comb_key.to_bytes());
                    let key_shares = key_shares
                        .into_iter()
                        .map(|s| bs58_encode(&s.to_bytes()))
                        .collect::<Vec<_>>();

                    for (idx, key_share) in key_shares.iter().enumerate() {
                        let path = out.join(format!("{idx}.env"));
                        let mut env_file = File::options().append(true).create(true).open(&path)?;
                        writeln!(env_file, "TIMEBOOST_PRIVATE_DECRYPTION_KEY={}", key_share)?;
                        writeln!(env_file, "TIMEBOOST_ENCRYPTION_KEY={}", pub_key)?;
                        writeln!(env_file, "TIMEBOOST_COMBINATION_KEY={}", comb_key)?;
                        debug!("private decryption key written to {}", path.display());
                    }
                    info!(
                        "generated threshold encryption keyset with:\nTIMEBOOST_ENCRYPTION_KEY={}\nTIMEBOOST_COMBINATION_KEY={}",
                        pub_key, comb_key
                    );
                } else {
                    for f in TEST_CONFIG_FILES {
                        let path = PathBuf::from("test-configs").join(f);
                        debug!(
                            "updating {} with new decryption keys",
                            path.to_str().unwrap()
                        );
                        todo!("blocked by https://github.com/EspressoSystems/timeboost/issues/355");
                    }
                }
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
/// Without `--out`, generated keys will update all `test-configs/*.json` configs;
/// Else, generated secret keys are written to a file in .env format, which can directly be used to
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
    out: Option<PathBuf>,
}

fn parse_seed(s: &str) -> Result<[u8; 32], anyhow::Error> {
    let bytes = hex::decode(s)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("invalid seed length: {} (expected 32)", bytes.len()))
}

fn gen_default_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::rng().fill(&mut seed);
    seed
}

fn main() -> anyhow::Result<()> {
    logging::init_logging();

    let cli = Cli::parse();
    debug!(
        "Generating {} keypairs for {:?} scheme",
        cli.num, cli.scheme
    );

    let seed = cli.seed.unwrap_or_else(|| {
        debug!("No seed provided, generating a random seed");
        gen_default_seed()
    });
    let num = NonZeroUsize::new(cli.num).expect("committee size greater than zero");

    if let Some(out) = cli.out.clone() {
        // Create output dir if necessary.
        fs::create_dir_all(&out)?;
        // write seed to a special `.seed` file
        let mut env_file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(out.join(".seed"))?;
        writeln!(env_file, "TIMEBOOST_SIGNATURE_SEED={}", hex::encode(seed))?;
    }
    cli.scheme.generate(seed, num, cli.out)?;

    Ok(())
}
