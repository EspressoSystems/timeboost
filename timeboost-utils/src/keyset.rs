use std::{fmt, fs, path::Path, time::Duration};

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
        Self::read_string(&data)
    }

    pub fn read_string(s: &str) -> Result<Self> {
        let conf = serde_json::from_str(s)?;
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

#[cfg(test)]
mod tests {
    const CONFIG: &str = r#"
    {
      "keyset": [
        {
          "sailfish_address": "127.0.0.1:8000",
          "decrypt_address": "127.0.0.1:10000",
          "producer_address": "127.0.0.1:11000",
          "signing_key": "io8tNQZ3HB8UAf7tUVtETTByFscDx16FTesmmUThuRNs",
          "dh_key": "3R87Pcd8nDyv6snoyv5rnwaQjvBpmjfux7kVDTyqeq5R",
          "private": {
            "signing_key": "GzdoPBXYWqsYxVEApJCHEkw9j9yDBvcMCthGLSzaDibp",
            "dh_key": "ABq61FVoQURtK9quBHDGnP1kGKRM1Z8b7qt4TKcUZtHQ",
            "dec_share": "j6QGWbskmmJXaKB1b6rx2ikMaZ9oBrejrBnfEKvqSz3TFm"
          }
        }
      ],
      "dec_keyset": {
        "pubkey": "kXGwgxdDHwJ8zWV72kSRr3FBGbQL7p7pmzEUhrz6webut3",
        "combkey": "7YBXwEN1WAfTCPyPdumpL7TtfQtTWkLJmL7rAMASxY8tEcw"
      }
    }
    "#;

    use super::KeysetConfig;

    #[test]
    fn serialisation_roundtrip() {
        let a = KeysetConfig::read_string(CONFIG).unwrap();
        let b = KeysetConfig::read_string(&a.to_string()).unwrap();
        assert_eq!(a.keyset.len(), b.keyset.len());
        for (a, b) in a.keyset.iter().zip(&b.keyset) {
            assert_eq!(a.sailfish_address, b.sailfish_address);
            assert_eq!(a.decrypt_address, b.decrypt_address);
            assert_eq!(a.producer_address, b.producer_address);
            assert_eq!(a.signing_key, b.signing_key);
            assert_eq!(a.dh_key, b.dh_key);
            let a = a.private.as_ref().unwrap();
            let b = b.private.as_ref().unwrap();
            assert_eq!(a.signing_key, b.signing_key);
            assert_eq!(a.dh_key, b.dh_key);
        }
    }
}
