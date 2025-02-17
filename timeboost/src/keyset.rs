use std::{collections::HashMap, fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use multisig::SecretKey;
use serde::Deserialize;
use serde_json::from_str;
use timeboost_crypto::{traits::threshold_enc::ThresholdEncScheme, DecryptionScheme};
use tokio::{net::lookup_host, time::sleep};

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
    pub sig_pk: String,
    pub dec_pk: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PublicDecInfo {
    pub pubkey: String,
    pub combkey: String,
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

pub async fn resolve_with_retries(host: &str) -> SocketAddr {
    loop {
        if let Ok(mut addresses) = lookup_host(host).await {
            if let Some(addr) = addresses.next() {
                break addr;
            }
        }
        sleep(Duration::from_secs(2)).await;
        tracing::error!(%host, "looking up peer host");
    }
}

/// NON PRODUCTION
/// This function takes a host IP address and checks if it's an ip address. If it is, it moves on, if not, it
/// loops until the DNS resolves to a 200 on the healthz endpoint.
pub async fn wait_for_live_peer(host: &str) -> Result<()> {
    if host.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }

    loop {
        // This is hacky. First, split on the port `:` that we know is in the string so we can get port 8800 instead
        let mut parts = host.split(':');
        let ip = parts.next().context("getting ip from host string")?;

        // The port will be 8000 + index, so we just add 800 to it
        let port: u16 = parts
            .next()
            .context("getting port from host string")?
            .parse()?;

        let new_host = format!("{}:{}", ip, port + 800u16);

        tracing::info!("establishing connection to load balancer at {new_host}");

        // Check if the healthz endpoint returns a 200 on the new host, looping forever until it does
        if reqwest::get(&new_host).await?.status() == 200 {
            return Ok(());
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
