use std::iter::once;
use std::num::NonZeroUsize;
use std::time::Duration;

use metrics::NoMetrics;
use timeboost_sequencer::{Output, Sequencer};
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::{gen_bundles, make_configs};

const NUM_OF_TRANSACTIONS: usize = 500;
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
    let (_enc_key, cfg) = make_configs(num, RECOVER_INDEX);

    let mut rxs = Vec::new();
    let mut tasks = JoinSet::new();
    let (bcast, _) = broadcast::channel(3);
    let finish = CancellationToken::new();

    // We spawn each sequencer into a task and broadcast new transactions to
    // all of them. Each sequencer pushes the transaction it produced into an
    // unbounded channel which we later compare with each other.
    for c in cfg.into_iter().map(|(c, _)| c) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut brx = bcast.subscribe();
        let finish = finish.clone();
        tasks.spawn(async move {
            if c.is_recover() {
                // delay start of a recovering node:
                sleep(Duration::from_secs(5)).await
            }
            let mut s = Sequencer::new(c, &NoMetrics).await.unwrap();
            loop {
                select! {
                    trx = brx.recv() => match trx {
                        Ok(trx) => s.add_bundles(once(trx)),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(err) => panic!("{err}")
                    },
                    out = s.next() => {
                        let Output::Transactions { transactions, .. } = out.unwrap() else {
                            continue
                        };
                        for t in transactions {
                            tx.send(t).unwrap()
                        }
                    }
                    _ = finish.cancelled() => {
                        info!(node = %s.public_key(), "done");
                        return
                    }
                }
            }
        });
        rxs.push(rx)
    }

    // wait until DKG is done
    // enc_key.wait().await;
    // tracing::info!("DKG done");

    // FIXME: (alex) after DKG catchup, we use actual enc_key above
    // currently late-joining nodes might never finish its DKG because sailfish vertices are pruned
    // thus, we only generate non-encrypted bundles for now
    let enc_key_tmp = timeboost_crypto::prelude::ThresholdEncKeyCell::default();
    tasks.spawn(gen_bundles(enc_key_tmp, bcast.clone()));

    for _ in 0..NUM_OF_TRANSACTIONS {
        let first = rxs[0].recv().await.unwrap();
        for rx in &mut rxs[1..] {
            let t = rx.recv().await.unwrap();
            assert_eq!(first.hash(), t.hash())
        }
    }

    finish.cancel();

    while let Some(result) = tasks.join_next().await {
        if let Err(err) = result {
            panic!("task panic: {err}")
        }
    }
}
