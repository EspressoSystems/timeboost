use std::net::IpAddr;
use std::num::NonZeroU8;
use std::{io, iter};

use anyhow::{Result, bail};
use ark_std::rand::SeedableRng as _;
use clap::{Parser, ValueEnum};
use cliquenet::Address;
use multisig::x25519;
use secp256k1::rand::SeedableRng as _;
use timeboost_utils::keyset::{KeysetConfig, NodeInfo, PrivateKeys};
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

    /// The first certifier address.
    #[clap(long, short)]
    certifier_base_addr: Address,

    /// The internal API address.
    #[clap(long, short)]
    internal_base_addr: Address,

    /// RNG seed for deterministic key generation
    #[clap(long)]
    seed: Option<u64>,

    /// Address modification mode.
    #[clap(long, short, default_value = "increment-port")]
    mode: Mode,

    /// The address of the Arbitrum Nitro node listener where we forward inclusion list to.
    #[clap(long)]
    nitro_addr: Option<Address>,
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
    fn mk_config(&self, seed: Option<u64>) -> Result<KeysetConfig> {
        let num_nodes: u8 = self.num.into();
        let mut s_rng = secp256k1::rand::rngs::StdRng::seed_from_u64(
            seed.map(|s| s.wrapping_pow(2)).unwrap_or_else(rand::random),
        );
        let mut d_rng = secp256k1::rand::rngs::StdRng::seed_from_u64(
            seed.map(|s| s.wrapping_pow(3)).unwrap_or_else(rand::random),
        );
        let mut p_rng = ark_std::rand::rngs::StdRng::seed_from_u64(
            seed.map(|s| s.wrapping_pow(4)).unwrap_or_else(rand::random),
        );

        // Generate multisig keypair
        let signing_keys: Vec<_> =
            iter::repeat_with(move || multisig::Keypair::generate_with_rng(&mut s_rng))
                .take(num_nodes as usize)
                .collect();
        // Generate x25519 keypair
        let auth_keys: Vec<_> =
            iter::repeat_with(move || x25519::Keypair::generate_with_rng(&mut d_rng).unwrap())
                .take(num_nodes as usize)
                .collect();
        // Generate HPKE keypair for this node using p_rng
        let encryption_keys: Vec<_> =
            iter::repeat_with(move || timeboost_crypto::prelude::HpkeDecKey::rand(&mut p_rng))
                .take(num_nodes as usize)
                .collect();

        let configs: Vec<_> = signing_keys
            .into_iter()
            .enumerate()
            .zip(auth_keys)
            .zip(encryption_keys)
            .map(|(((i, kp), xp), hpke)| NodeInfo {
                sailfish_address: self.adjust_addr(i as u8, &self.sailfish_base_addr).unwrap(),
                decrypt_address: self.adjust_addr(i as u8, &self.decrypt_base_addr).unwrap(),
                certifier_address: self
                    .adjust_addr(i as u8, &self.certifier_base_addr)
                    .unwrap(),
                internal_address: self.adjust_addr(i as u8, &self.internal_base_addr).unwrap(),
                signing_key: kp.public_key(),
                dh_key: xp.public_key(),
                enc_key: timeboost_crypto::prelude::HpkeEncKey::from(&hpke),
                private: Some(PrivateKeys {
                    signing_key: kp.secret_key(),
                    dh_key: xp.secret_key(),
                    dec_key: hpke,
                }),
                nitro_addr: self.nitro_addr.clone(),
            })
            .collect();
        Ok(KeysetConfig { keyset: configs })
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
    let cfg = args.mk_config(args.seed)?;
    serde_json::to_writer(io::stdout(), &cfg)?;

    Ok(())
}
