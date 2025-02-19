use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};

use committable::Committable;
use multisig::{Committee, Keypair, PublicKey};
use sailfish_net::{Address, Network, NetworkMetrics};

use crate::metrics::SailfishMetrics;
use crate::rbc::{Rbc, RbcConfig};
use crate::{consensus::Consensus, coordinator::Coordinator};

pub async fn setup<B, P, A1, A2>(
    keys: Keypair,
    peers: P,
    addr: A2,
    m1: SailfishMetrics,
    m2: NetworkMetrics) -> Result<Coordinator<B, Rbc<B>>>
where
    B: Committable + Eq + Clone + DeserializeOwned + Serialize + Sync + Send + 'static,
    P: IntoIterator<Item = (PublicKey, A1)> + Clone,
    A1: Into<Address>,
    A2: Into<Address>
{
    let net = Network::create(addr, keys.clone(), peers.clone(), m2).await?;
    let parties = Committee::new(
        peers.clone()
            .into_iter()
            .map(|b| b.0)
            .enumerate()
            .map(|(i, key)| (i as u8, key)),
    );
    let rbc = Rbc::new(net, RbcConfig::new(keys.clone(), parties.clone()));
    let cons = Consensus::new(keys, parties).with_metrics(m1);
    Ok(Coordinator::new(rbc, cons))
}
