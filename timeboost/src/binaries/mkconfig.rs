use std::net::IpAddr;
use std::num::NonZeroU8;
use std::{io, iter};

use anyhow::{Result, bail};
use ark_std::rand::SeedableRng as _;
use clap::{Parser, ValueEnum};
use cliquenet::Address;
use multisig::x25519;
use secp256k1::rand::SeedableRng as _;
use timeboost_crypto::{DecryptionScheme, TrustedKeyMaterial};
use timeboost_utils::keyset::{KeysetConfig, NodeInfo, PrivateKeys, PublicDecInfo};
use timeboost_utils::types::logging;

#[derive(Clone, Debug, Parser)]
struct Args {
    /// How many nodes should configuration contain?
    #[clap(long, short = 'n')]
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

    /// RNG seed for deterministic key generation
    #[clap(long)]
    seed: Option<u64>,

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
    fn mk_node_infos(
        &self,
        dec: &TrustedKeyMaterial,
        seed: Option<u64>,
    ) -> impl Iterator<Item = Result<NodeInfo>> {
        let num_nodes: u8 = self.num.into();
        let num_nodes = num_nodes as usize;
        let (signing_keys, dh_keys) = match seed {
            Some(s) => {
                let mut sign_rng = secp256k1::rand::rngs::StdRng::seed_from_u64(s.wrapping_pow(2));
                let mut dh_rng = secp256k1::rand::rngs::StdRng::seed_from_u64(s.wrapping_pow(3));

                (
                    iter::repeat_with(|| multisig::Keypair::generate_with_rng(&mut sign_rng))
                        .take(num_nodes)
                        .collect::<Vec<_>>(),
                    iter::repeat_with(|| x25519::Keypair::generate_with_rng(&mut dh_rng).unwrap())
                        .take(num_nodes)
                        .collect::<Vec<_>>(),
                )
            }
            None => (
                iter::repeat_with(multisig::Keypair::generate)
                    .take(num_nodes)
                    .collect::<Vec<_>>(),
                iter::repeat_with(|| x25519::Keypair::generate().unwrap())
                    .take(num_nodes)
                    .collect::<Vec<_>>(),
            ),
        };
        signing_keys
            .into_iter()
            .zip(dh_keys)
            .zip(&dec.2)
            .enumerate()
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

    let tkm = match args.seed {
        Some(seed) => {
            let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(seed);
            DecryptionScheme::trusted_keygen_with_rng(args.num.into(), &mut rng)
        }
        None => DecryptionScheme::trusted_keygen(args.num.into()),
    };
    let cfg = KeysetConfig {
        keyset: args.mk_node_infos(&tkm, args.seed).collect::<Result<_>>()?,
        dec_keyset: PublicDecInfo {
            pubkey: tkm.0.clone(),
            combkey: tkm.1.clone(),
        },
    };
    serde_json::to_writer(io::stdout(), &cfg)?;

    Ok(())
}
