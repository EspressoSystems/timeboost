mod block_order;
mod test_timeboost_startup;
mod transaction_order;

use std::net::Ipv4Addr;

use cliquenet::Address;
use multisig::Keypair;
use timeboost_builder::BlockProducerConfig;
use timeboost_crypto::DecryptionScheme;
use timeboost_crypto::TrustedKeyMaterial;
use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;
use timeboost_sequencer::SequencerConfig;
use timeboost_types::BundleVariant;
use timeboost_types::DecryptionKey;
use timeboost_utils::load_generation::make_bundle;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;

fn make_configs<R>(
    (pubkey, combkey, shares): &TrustedKeyMaterial,
    recover_index: R,
) -> Vec<(SequencerConfig, BlockProducerConfig)>
where
    R: Into<Option<usize>>,
{
    let parts = shares
        .iter()
        .cloned()
        .map(|s| {
            let p1 = portpicker::pick_unused_port().unwrap();
            let p2 = portpicker::pick_unused_port().unwrap();
            let p3 = portpicker::pick_unused_port().unwrap();
            let a1 = Address::from((Ipv4Addr::LOCALHOST, p1));
            let a2 = Address::from((Ipv4Addr::LOCALHOST, p2));
            let a3 = Address::from((Ipv4Addr::LOCALHOST, p3));
            (Keypair::generate(), a1, a2, a3, s)
        })
        .collect::<Vec<_>>();

    let sailfish_peers = parts
        .iter()
        .map(|(kp, sa, ..)| (kp.public_key(), sa.clone()))
        .collect::<Vec<_>>();

    let decrypt_peers = parts
        .iter()
        .map(|(kp, _, da, ..)| (kp.public_key(), da.clone()))
        .collect::<Vec<_>>();

    let produce_peers = parts
        .iter()
        .map(|(kp, _, _, pa, ..)| (kp.public_key(), pa.clone()))
        .collect::<Vec<_>>();

    let mut cfgs = Vec::new();
    let recover_index = recover_index.into();

    for (i, (kpair, sa, da, pa, share)) in parts.iter().cloned().enumerate() {
        let dkey = DecryptionKey::new(pubkey.clone(), combkey.clone(), share.clone());
        let mut cfg = SequencerConfig::new(kpair.clone(), dkey, sa, da)
            .with_sailfish_peers(sailfish_peers.clone())
            .with_decrypt_peers(decrypt_peers.clone());
        if let Some(r) = recover_index {
            cfg = cfg.recover(i == r);
        }
        let pcf = BlockProducerConfig::new(kpair, pa).with_peers(produce_peers.clone());
        cfgs.push((cfg, pcf));
    }

    cfgs
}

/// Generate random bundles at a fixed frequency.
async fn gen_bundles(
    pubkey: <DecryptionScheme as ThresholdEncScheme>::PublicKey,
    tx: broadcast::Sender<BundleVariant>,
) {
    loop {
        let Ok(b) = make_bundle(&pubkey) else {
            warn!("Failed to generate bundle");
            continue;
        };
        if tx.send(b).is_err() {
            warn!("Failed to broadcast bundle");
            return;
        }
        sleep(Duration::from_millis(10)).await
    }
}
