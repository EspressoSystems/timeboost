use std::iter::once;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use metrics::NoMetrics;
use timeboost_builder::BlockProducer;
use timeboost_crypto::DecryptionScheme;
use timeboost_sequencer::Sequencer;
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Barrier, broadcast, mpsc};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::{debug, info};

use super::{gen_bundles, make_configs};

const NUM_OF_BLOCKS: usize = 50;
const RECOVER_INDEX: usize = 2;

#[tokio::test]
async fn block_order() {
    init_logging();

    let num = NonZeroUsize::new(5).unwrap();
    let dec = DecryptionScheme::trusted_keygen(num);
    let cfg = make_configs(&dec, RECOVER_INDEX);

    let mut rxs = Vec::new();
    let mut tasks = JoinSet::new();
    let (bcast, _) = broadcast::channel(3);
    let finish = Arc::new(Barrier::new(5));

    for (c, b) in cfg {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut brx = bcast.subscribe();
        let finish = finish.clone();
        tasks.spawn(async move {
            if c.is_recover() {
                // delay start of a recovering node:
                sleep(Duration::from_secs(5)).await
            }
            let mut s = Sequencer::new(c, &NoMetrics).await.unwrap();
            let mut p = BlockProducer::new(b, &NoMetrics).await.unwrap();
            let mut i = 0;
            while i < NUM_OF_BLOCKS {
                select! {
                    t = brx.recv() => match t {
                        Ok(trx) => s.add_bundles(once(trx)),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(err) => panic!("{err}")
                    },
                    t = s.next_transactions() => {
                        let (t, _, _) = t.expect("transaction");
                        p.enqueue(t).await.unwrap()
                    }
                    b = p.next_block() => {
                        debug!(node = %s.public_key(), blocks = %i);
                        let b = b.expect("block");
                        i += 1;
                        p.gc(b.num()).await.unwrap();
                        tx.send(b).unwrap()
                    }
                }
            }
            finish.wait().await;
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
