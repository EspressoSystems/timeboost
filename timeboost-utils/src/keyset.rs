use std::{fmt, fs, path::Path, time::Duration};

use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::{HpkeDecKey, HpkeEncKey};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetConfig {
    pub keyset: Vec<NodeInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub sailfish_address: Address,
    pub decrypt_address: Address,
    pub certifier_address: Address,
    pub internal_address: Address,
    pub signing_key: multisig::PublicKey,
    pub dh_key: x25519::PublicKey,

    /// public key in hybrid public key encryption (HPKE) for secure communication
    #[serde(with = "hpkeenckey")]
    pub enc_key: HpkeEncKey,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro_addr: Option<Address>,

    #[serde(default)]
    pub private: Option<PrivateKeys>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKeys {
    pub signing_key: multisig::SecretKey,
    pub dh_key: x25519::SecretKey,
    /// secret key in hybrid public key encryption (HPKE) for secure communication
    #[serde(with = "hpkedeckey")]
    pub dec_key: HpkeDecKey,
}

impl KeysetConfig {
    pub fn read_keyset<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read_to_string(path)?;
        Self::read_string(&data)
    }

    pub fn read_string(s: &str) -> Result<Self> {
        let conf = serde_json::from_str(s)?;
        Ok(conf)
    }
}

impl fmt::Display for KeysetConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = serde_json::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

macro_rules! mk_serde_mod {
    ($module:ident, $type:ident) => {
        mod $module {
            use super::$type;
            use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

            pub fn serialize<S>(x: &$type, s: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                bs58::encode(x.to_bytes()).into_string().serialize(s)
            }

            pub fn deserialize<'de, D>(d: D) -> Result<$type, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(d)?;
                let v = bs58::decode(&s).into_vec().map_err(de::Error::custom)?;
                let c = bincode::config::standard().with_limit::<8192>();
                let k = bincode::serde::decode_from_slice(&v, c).map_err(de::Error::custom)?;
                Ok(k.0)
            }
        }
    };
}

mk_serde_mod!(hpkeenckey, HpkeEncKey);
mk_serde_mod!(hpkedeckey, HpkeDecKey);

/// NON PRODUCTION
/// This function takes the provided host and hits the healthz endpoint. This to ensure that when
/// initiating the network TCP stream that we do not try to hit a dead host, causing issues with
/// network startup.
pub async fn wait_for_live_peer(mut host: Address) -> Result<()> {
    if host.is_ip() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    // The port is always 8800 + node index. We need to increment the port by one because we are
    // using the cli port for sailfish in our default config.
    host.set_port(800 + host.port());

    loop {
        let url = format!("http://{host}/v0/healthz");
        tracing::info!(%host, %url, "establishing connection to load balancer");

        // Check if the healthz endpoint returns a 200 on the new host, looping forever until it
        // does
        match client.get(&url).send().await {
            Ok(resp) => {
                tracing::info!("got response {resp:?}, status {}", resp.status());
                if resp.status() == 200 {
                    return Ok(());
                }
            }
            Err(e) => tracing::error!("failed to send request: {}", e),
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
}

#[cfg(test)]
mod tests {
    // generated via `just mkconfig_local 1 --seed 42`
    const CONFIG: &str = r#"
{
  "keyset": [
    {
      "sailfish_address": "127.0.0.1:8000",
      "decrypt_address": "127.0.0.1:10000",
      "certifier_address": "127.0.0.1:11000",
      "internal_address": "127.0.0.1:5000",
      "signing_key": "eiwaGN1NNaQdbnR9FsjKzUeLghQZsTLPjiL4RcQgfLoX",
      "dh_key": "AZrLbV37HAGhBWh49JHzup6Wfpu2AAGWGJJnxCDJibiY",
      "enc_key": "8t9PdQ61NwF9n7RU1du43C95ndSs6jn2EM7gRCfutVo2YXh6dyXAJiEWhpfYtPUv9gK",
      "private": {
        "signing_key": "3hzb3bRzn3dXSV1iEVE6mU4BF2aS725s8AboRxLwULPp",
        "dh_key": "BB3zUfFQGfw3sL6bpp1JH1HozK6ehEDmRGoiCpQH62rZ",
        "dec_share": "jbJKBjBMYvZhrtFwzDohY5rWSvVSsSu2X5qjQyFJAZQCcF",
        "dec_key": "AgrGYiNQMqPpLgwPTuCV5aww6kpcoAQnf4xuFukTEtkL1"
      }
    }
  ],
  "dec_keyset": {
    "pubkey": "8sz9Bu5ECvR42x69tBm2W8GaaMrm1LQnm9rmT3EL5EdbPP3TqrLUyoUkxBzpCzPy4Vu",
    "combkey": "rL1WRpSHwV538SENbbFRaMTARrK3h9WhgTx5wzb5E78QsjdHMkEnEQeDXgeEdXSvvsR"
  }
}
    "#;

    use super::KeysetConfig;

    #[test]
    fn serialisation_roundtrip() {
        let a = KeysetConfig::read_string(CONFIG).unwrap();
        let b = KeysetConfig::read_string(&a.to_string()).unwrap();
        assert_eq!(a, b);
    }
}
