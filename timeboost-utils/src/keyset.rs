use std::{collections::HashMap, fs, path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use cliquenet::Address;
use multisig::{SecretKey, x25519};
use serde::{Deserialize, Serialize};
use serde_json::from_str;
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
    pub sailfish_url: Address,
    pub decrypt_url: Address,
    pub producer_url: Address,
    pub signing_key: multisig::PublicKey,
    pub dh_key: x25519::PublicKey,

    #[serde(default)]
    pub private: Option<PrivateKeys>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKeys {
    /// Signing key.
    pub sig: multisig::SecretKey,
    /// DH key.
    pub dh: x25519::SecretKey,
    /// Threshold decryption key.
    pub dec: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicDecInfo {
    pub pubkey: String,
    pub combkey: String,
}

impl PublicDecInfo {
    pub fn pubkey(&self) -> Result<PublicKey> {
        PublicKey::try_from_str::<8192>(self.pubkey.as_str())
            .context("Failed to parse public key from keyset")
    }
}

impl KeysetConfig {
    pub fn read_keyset(path: &Path) -> Result<Self> {
        ensure!(path.exists(), "File not found: {:?}", path);
        let data = fs::read_to_string(path).context("Failed to read file")?;
        let keyset: KeysetConfig = from_str(&data).context("Failed to parse JSON")?;
        Ok(keyset)
    }

    pub fn build_decryption_material(&self, deckey: KeyShare) -> Result<DecryptionKey> {
        let pubkey = PublicKey::try_from_str::<8192>(self.dec_keyset.pubkey.as_str())
            .context("Failed to parse public key from keyset")?;
        let combkey = CombKey::try_from_str::<8192>(self.dec_keyset.combkey.as_str())
            .context("Failed to parse combination key from keyset")?;
        Ok(DecryptionKey::new(pubkey, combkey, deckey))
    }

    pub fn keyset(&self) -> &[NodeInfo] {
        &self.keyset
    }

    pub fn dec_keyset(&self) -> &PublicDecInfo {
        &self.dec_keyset
    }
}

impl PrivateKeys {
    pub fn read<P: AsRef<Path>>(key_file: P) -> Result<Self> {
        let vars = dotenvy::from_path_iter(key_file)?.collect::<Result<HashMap<_, _>, _>>()?;
        let sig = vars
            .get("TIMEBOOST_PRIVATE_SIGNATURE_KEY")
            .context("key file missing TIMEBOOST_PRIVATE_SIGNATURE_KEY")?
            .as_str()
            .try_into()
            .context("invalid value for TIMEBOOST_PRIVATE_SIGNATURE_KEY")?;
        let dh = vars
            .get("TIMEBOOST_PRIVATE_DH_KEY")
            .cloned()
            .context("key file missing TIMEBOOST_PRIVATE_DH_KEY")?
            .as_str()
            .try_into()
            .context("invalid value for TIMEBOOST_PRIVATE_DH_KEY")?;
        let dec = vars
            .get("TIMEBOOST_PRIVATE_DECRYPTION_KEY")
            .cloned()
            .context("key file missing TIMEBOOST_PRIVATE_DECRYPTION_KEY")?;
        Ok(Self { sig, dh, dec })
    }

    pub fn parse(&self) -> Result<(SecretKey, x25519::SecretKey, KeyShare)> {
        let dec: KeyShare = bincode::serde::decode_from_slice(
            &bs58::decode(&*self.dec).into_vec()?,
            bincode::config::standard(),
        )
        .map(|(val, _)| val)?;
        Ok((self.sig.clone(), self.dh.clone(), dec))
    }
}

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

    // The port is always 8800 + node index. We need to increment the port by one because we are using
    // the cli port for sailfish in our default config.
    host.set_port(800 + host.port());

    loop {
        let url = format!("http://{host}/v0/healthz");
        tracing::info!(%host, %url, "establishing connection to load balancer");

        // Check if the healthz endpoint returns a 200 on the new host, looping forever until it does
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
