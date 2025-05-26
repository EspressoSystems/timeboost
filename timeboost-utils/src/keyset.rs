use std::{fs, path::Path, time::Duration};

use anyhow::Result;
use cliquenet::Address;
use multisig::x25519;
use serde::{Deserialize, Serialize};
use timeboost_crypto::{DecryptionScheme, traits::threshold_enc::ThresholdEncScheme};
use timeboost_types::DecryptionKey;

type KeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
type PublicKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;
type CombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;

#[derive(Serialize, Deserialize)]
pub struct KeysetConfig {
    pub keyset: Vec<NodeInfo>,
    pub dec_keyset: PublicDecInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub sailfish_address: Address,
    pub decrypt_address: Address,
    pub producer_address: Address,
    pub signing_key: multisig::PublicKey,
    pub dh_key: x25519::PublicKey,

    #[serde(default)]
    pub private: Option<PrivateKeys>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKeys {
    pub signing_key: multisig::SecretKey,
    pub dh_key: x25519::SecretKey,
    #[serde(with = "keyshare")]
    pub dec_share: KeyShare,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicDecInfo {
    #[serde(with = "pubkey")]
    pub pubkey: PublicKey,
    #[serde(with = "combkey")]
    pub combkey: CombKey,
}

impl KeysetConfig {
    pub fn read_keyset<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read_to_string(path)?;
        let conf = serde_json::from_str(&data)?;
        Ok(conf)
    }

    pub fn decryption_key(&self, share: KeyShare) -> DecryptionKey {
        DecryptionKey::new(
            self.dec_keyset.pubkey.clone(),
            self.dec_keyset.combkey.clone(),
            share,
        )
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

mk_serde_mod!(keyshare, KeyShare);
mk_serde_mod!(pubkey, PublicKey);
mk_serde_mod!(combkey, CombKey);

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
