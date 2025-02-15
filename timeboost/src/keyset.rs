use std::{collections::HashMap, fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use multisig::SecretKey;
use serde::Deserialize;
use serde_json::from_str;
use serde_with::serde_as;
use timeboost_crypto::{traits::threshold_enc::ThresholdEncScheme, DecryptionScheme};
use tokio::{net::lookup_host, time::sleep};

type KeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
type PublicKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;
type CombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;

#[derive(Clone, Debug, Deserialize)]
pub struct Keyset {
    pub keyset: Vec<PublicNodeInfo>,
    pub dec_keyset: PublicDecInfo,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
pub struct PublicNodeInfo {
    pub url: String,
    pub pubkey: String,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
pub struct PublicDecInfo {
    pub pubkey: String,
    pub combkey: String,
}
pub struct DecryptionInfo {
    pub pubkey: PublicKey,
    pub combkey: CombKey,
    pub privkey: KeyShare,
}

// Helper methods for parsing keyset data
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

pub fn read_keyset(path: PathBuf) -> Result<Keyset> {
    ensure!(path.exists(), "File not found: {:?}", path);
    let data = fs::read_to_string(&path).context("Failed to read file")?;
    let keyset: Keyset = from_str(&data).context("Failed to parse JSON")?;
    Ok(keyset)
}

pub fn build_decryption_material(deckey: KeyShare, keyset: Keyset) -> Result<DecryptionInfo> {
    let pubkey = PublicKey::try_from(&keyset.dec_keyset.pubkey)
        .context("Failed to parse public key from keyset")?;
    let combkey = CombKey::try_from(&keyset.dec_keyset.combkey)
        .context("Failed to parse combination key from keyset")?;
    Ok(DecryptionInfo {
        pubkey,
        combkey,
        privkey: deckey,
    })
}

pub fn private_keys(
    key_file: Option<PathBuf>,
    private_signature_key: Option<String>,
    private_decryption_key: Option<String>,
) -> Result<(SecretKey, KeyShare)> {
    if let Some(path) = key_file {
        let vars = dotenvy::from_path_iter(path)?.collect::<Result<HashMap<_, _>, _>>()?;
        let sig_key_string = vars
            .get("TIMEBOOST_PRIVATE_SIGNATURE_KEY")
            .context("key file missing TIMEBOOST_PRIVATE_SIGNATURE_KEY")?;
        let sig_key = multisig::SecretKey::try_from(sig_key_string)?;
        let dec_key_string = vars
            .get("TIMEBOOST_PRIVATE_DECRYPTION_KEY")
            .context("key file missing TIMEBOOST_PRIVATE_DECRYPTION_KEY")?;
        let dec_key: KeyShare = bincode::deserialize(&bs58::decode(dec_key_string).into_vec()?)?;

        Ok((sig_key, dec_key))
    } else if let (Some(sig_key), Some(dec_key)) = (private_signature_key, private_decryption_key) {
        let sig_key = multisig::SecretKey::try_from(&sig_key)?;
        let bytes = &bs58::decode(dec_key)
            .into_vec()
            .context("unable to decode bs58")?;
        let dec_key =
            bincode::deserialize::<KeyShare>(bytes).expect("unable to read bytes into keyshare");

        Ok((sig_key, dec_key))
    } else {
        bail!("neither key file nor full set of private keys was provided")
    }
}
