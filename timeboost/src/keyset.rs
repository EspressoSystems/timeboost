use std::{collections::HashMap, fs, path::PathBuf, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use clique_net::Address;
use multisig::SecretKey;
use serde::Deserialize;
use serde_json::from_str;
use timeboost_crypto::{traits::threshold_enc::ThresholdEncScheme, DecryptionScheme};

type KeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
type PublicKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;
type CombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;

#[derive(Deserialize)]
pub struct Keyset {
    keyset: Vec<PublicNodeInfo>,
    dec_keyset: PublicDecInfo,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PublicNodeInfo {
    pub url: String,
    pub pubkey: String,

    /// The optional signature private key for this node.
    #[serde(default)]
    pub sig_pk: Option<String>,

    /// The optional decryption private key for this node.
    #[serde(default)]
    pub dec_pk: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PublicDecInfo {
    pubkey: String,
    combkey: String,
}

#[allow(dead_code)]
pub struct DecryptionInfo {
    pub pubkey: PublicKey,
    pub combkey: CombKey,
    pub privkey: KeyShare,
}

impl Keyset {
    pub fn read_keyset(path: PathBuf) -> Result<Self> {
        ensure!(path.exists(), "File not found: {:?}", path);
        let data = fs::read_to_string(&path).context("Failed to read file")?;
        let keyset: Keyset = from_str(&data).context("Failed to parse JSON")?;
        Ok(keyset)
    }

    pub fn build_decryption_material(&self, deckey: KeyShare) -> Result<DecryptionInfo> {
        let pubkey = PublicKey::try_from(self.dec_keyset.pubkey.as_str())
            .context("Failed to parse public key from keyset")?;
        let combkey = CombKey::try_from(self.dec_keyset.combkey.as_str())
            .context("Failed to parse combination key from keyset")?;
        Ok(DecryptionInfo {
            pubkey,
            combkey,
            privkey: deckey,
        })
    }

    pub fn keyset(&self) -> &[PublicNodeInfo] {
        &self.keyset
    }
}

pub fn private_keys(
    key_file: Option<PathBuf>,
    private_signature_key: Option<String>,
    private_decryption_key: Option<String>,
) -> Result<(SecretKey, KeyShare)> {
    if let Some(path) = key_file {
        let vars = dotenvy::from_path_iter(path)?.collect::<Result<HashMap<_, _>, _>>()?;
        let sig_key_string: &str = vars
            .get("TIMEBOOST_PRIVATE_SIGNATURE_KEY")
            .context("key file missing TIMEBOOST_PRIVATE_SIGNATURE_KEY")?;
        let sig_key = multisig::SecretKey::try_from(sig_key_string)?;
        let dec_key_string = vars
            .get("TIMEBOOST_PRIVATE_DECRYPTION_KEY")
            .context("key file missing TIMEBOOST_PRIVATE_DECRYPTION_KEY")?;
        let dec_key: KeyShare = bincode::deserialize(&bs58::decode(dec_key_string).into_vec()?)?;

        Ok((sig_key, dec_key))
    } else if let (Some(sig_key), Some(dec_key)) = (private_signature_key, private_decryption_key) {
        let sig_key = multisig::SecretKey::try_from(sig_key.as_str())?;
        let bytes = &bs58::decode(dec_key)
            .into_vec()
            .context("unable to decode bs58")?;
        let dec_key = bincode::deserialize(bytes).expect("unable to read bytes into keyshare");

        Ok((sig_key, dec_key))
    } else {
        bail!("neither key file nor full set of private keys was provided")
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
        if let Ok(resp) = client.get(&url).send().await {
            tracing::info!("got response {resp:?}, status {}", resp.status());
            if resp.status() == 200 {
                return Ok(());
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
