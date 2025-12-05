use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use metrics::NoMetrics;
use multisig::Certificate;
use timeboost::builder::Certifier;
use timeboost::sequencer::{Output, Sequencer};
use timeboost::types::{Auction, Block, BlockInfo};
use timeboost_utils::logging::init_logging;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info};

use crate::tests::timeboost::{Round2Block, hash};

use super::{gen_bundles, make_configs};

const NUM_OF_BLOCKS: usize = 50;
const RECOVER_INDEX: usize = 2;

#[tokio::test]
async fn block_order() {
    init_logging();

    let num = NonZeroUsize::new(5).unwrap();
    let quorum = 4;
    let (enc_keys, cfg) = make_configs(num, RECOVER_INDEX).await;

    let chain_id = cfg[0].0.namespace();
    let auction = Auction::new(cfg[0].0.chain_config.auction_contract.unwrap());

    let mut rxs = Vec::new();
    let tasks = TaskTracker::new();
    let (bcast, _) = broadcast::channel(3);
    let finish = CancellationToken::new();
    let round2block = Arc::new(Round2Block::new());

    for (c, b) in cfg {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut brx = bcast.subscribe();
        let finish = finish.clone();
        let label = c.sign_keypair().public_key();
        let r2b = round2block.clone();
        tasks.spawn(async move {
            if c.is_recover() {
                // delay start of a recovering node:
                sleep(Duration::from_secs(5)).await
            }
            let mut s = Sequencer::new(c, &NoMetrics).await.unwrap();
            let mut p = Certifier::new(b, &NoMetrics).await.unwrap();
            let mut r = None;

            let handle = p.handle();
            loop {
                select! {
                    t = brx.recv() => match t {
                        Ok(trx) => s.add_bundle(trx).await.unwrap(),
                        Err(RecvError::Lagged(_)) => {
                            error!(node = %s.public_key(), "lagging behind");
                            continue
                        }
                        Err(err) => panic!("{err}")
                    },
                    o = s.next() => {
                        let Output::Transactions { round, transactions, .. } = o.unwrap() else {
                            error!(node = %s.public_key(), "no sequencer output");
                            continue
                        };
                        // We require unique round numbers.
                        if Some(round) == r {
                            continue
                        }
                        r = Some(round);
                        let i = r2b.get(round);
                        let b = Block::new(i, *round, hash(&transactions));
                        handle.enqueue(b).await.unwrap()
                    }
                    b = p.next_block() => {
                        let b = b.expect("block");
                        debug!(node = %s.public_key(), hash = %b.data().hash(), "block received");
                        let c: Certificate<BlockInfo> = b.into();
                        tx.send(c.into_data()).unwrap()
                    }
                    _ = finish.cancelled() => {
                        info!(node = %s.public_key(), "done");
                        return
                    }
                }
            }
        });
        rxs.push((label, rx))
    }

    for enc_key in &enc_keys {
        enc_key.read().await;
    }

    tasks.spawn(gen_bundles(
        bcast.clone(),
        chain_id,
        enc_keys[0].clone(),
        auction,
    ));

    let mut map: HashMap<BlockInfo, usize> = HashMap::new();

    for b in 0..NUM_OF_BLOCKS {
        map.clear();
        info!(block = %b);
        for (node, r) in &mut rxs {
            debug!(%node, block = %b, "awaiting ...");
            let info = r.recv().await.unwrap();
            *map.entry(info).or_default() += 1
        }
        if map.values().any(|n| *n >= quorum && *n <= num.get()) {
            continue;
        }
        for (info, n) in map {
            eprintln!("{}: {} = {n}", info.hash(), info.round().num())
        }
        panic!("outputs do not match")
    }

    finish.cancel();
}
