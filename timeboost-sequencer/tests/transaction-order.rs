use std::iter::once;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::time::Duration;

use metrics::NoMetrics;
use multisig::Keypair;
use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;
use timeboost_crypto::{DecryptionScheme, TrustedKeyMaterial};
use timeboost_sequencer::{Sequencer, SequencerConfig};
use timeboost_types::{BundleVariant, DecryptionKey};
use timeboost_utils::load_generation::make_bundle;
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::{debug, info, warn};

type EncKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;

const NUM_OF_BLOCKS: usize = 50;
const RECOVER_INDEX: usize = 2;

/// Run some timboost sequencer instances and check that they produce the
/// same sequence of transaction.
///
/// We include testing for round info recovery of a node by delaying the start
/// of one sequencer and configuring it to recover.
#[tokio::test]
async fn transaction_order() {
    init_logging();

    let num = NonZeroUsize::new(5).unwrap();
    let dec = DecryptionScheme::trusted_keygen(num);
    let cfg = make_configs(&dec);

    let mut rxs = Vec::new();
    let mut tasks = JoinSet::new();
    let (bcast, _) = broadcast::channel(3);

    // We spawn each sequencer into a task and broadcast new transactions to
    // all of them. Each sequencer pushes the transaction it produced into an
    // unbounded channel which we later compare with each other.
    for c in cfg {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut brx = bcast.subscribe();
        tasks.spawn(async move {
            if c.is_recover() {
                // delay start of a recovering node:
                sleep(Duration::from_secs(5)).await
            }
            let mut s = Sequencer::new(c, &NoMetrics).await.unwrap();
            let mut i = 0;
            while i < NUM_OF_BLOCKS {
                select! {
                    t = brx.recv() => match t {
                        Ok(trx) => s.add_bundles(once(trx)),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(err) => panic!("{err}")
                    },
                    b = s.next_block() => {
                        debug!(node = %s.public_key(), block = %i);
                        i += 1;
                        tx.send(b.unwrap()).unwrap()
                    }
                }
            }
            info!(node = %s.public_key(), "done")
        });
        rxs.push(rx)
    }

    tasks.spawn(gen_bundles(dec.0, bcast.clone()));

    for _ in 0..NUM_OF_BLOCKS {
        let first = rxs[0].recv().await.unwrap();
        for rx in &mut rxs[1..] {
            let b = rx.recv().await.unwrap();
            assert_eq!(first.cert().data(), b.cert().data())
        }
    }

    while let Some(result) = tasks.join_next().await {
        if let Err(err) = result {
            panic!("task panic: {err}")
        }
    }
}

fn make_configs((pubkey, combkey, shares): &TrustedKeyMaterial) -> Vec<SequencerConfig> {
    let parts = shares
        .iter()
        .cloned()
        .map(|share| {
            let p = portpicker::pick_unused_port().unwrap();
            (Keypair::generate(), (Ipv4Addr::LOCALHOST, p), share)
        })
        .collect::<Vec<_>>();

    let peers = parts.iter().map(|(k, a, _)| (k.public_key(), *a));

    let mut cfgs = Vec::new();
    for (i, (kpair, addr, share)) in parts.clone().into_iter().enumerate() {
        let dkey = DecryptionKey::new(pubkey.clone(), combkey.clone(), share);
        let cfg = SequencerConfig::new(kpair, dkey, addr)
            .with_peers(peers.clone())
            .recover(i == RECOVER_INDEX);
        cfgs.push(cfg)
    }
    cfgs
}

/// Generate random bundles at a fixed frequency.
async fn gen_bundles(pubkey: EncKey, tx: broadcast::Sender<BundleVariant>) {
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
