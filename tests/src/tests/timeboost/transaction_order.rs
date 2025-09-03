use std::collections::HashMap;
use std::iter::once;
use std::num::NonZeroUsize;
use std::time::Duration;

use alloy::primitives::B256;
use metrics::NoMetrics;
use sailfish_types::RoundNumber;
use timeboost::sequencer::{Output, Sequencer};
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info};

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
    let quorum = 4;
    let (enc_keys, cfg) = make_configs(num, RECOVER_INDEX);

    let mut rxs = Vec::new();
    let tasks = TaskTracker::new();
    let (bcast, _) = broadcast::channel(3);
    let finish = CancellationToken::new();

    // We spawn each sequencer into a task and broadcast new transactions to
    // all of them. Each sequencer pushes the transaction it produced into an
    // unbounded channel which we later compare with each other.
    for c in cfg.into_iter().map(|(c, _)| c) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut brx = bcast.subscribe();
        let finish = finish.clone();
        let label = c.sign_keypair().public_key();
        tasks.spawn(async move {
            if c.is_recover() {
                // delay start of a recovering node:
                sleep(Duration::from_secs(5)).await
            }
            let mut s = Sequencer::new(c.clone(), &NoMetrics).await.unwrap();
            loop {
                select! {
                    trx = brx.recv() => match trx {
                        Ok(trx) => s.add_bundles(once(trx)),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(err) => panic!("{err}")
                    },
                    out = s.next() => {
                        let Output::Transactions { round, transactions, .. } = out.unwrap() else {
                            continue
                        };
                        let transactions = transactions.into_iter().map(|t| *t.hash()).collect();
                        tx.send((round, transactions)).unwrap()
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

    tasks.spawn(gen_bundles(enc_keys[0].clone(), bcast.clone()));

    let mut map: HashMap<(RoundNumber, Vec<B256>), usize> = HashMap::new();
    let mut transactions = 0;

    while transactions < NUM_OF_TRANSACTIONS {
        map.clear();
        info!("{transactions}/{NUM_OF_TRANSACTIONS}");
        for (node, r) in &mut rxs {
            debug!(%node, "awaiting ...");
            let value = r.recv().await.unwrap();
            *map.entry(value).or_default() += 1
        }
        if let Some(((_, trxs), _)) = map.iter().find(|(_, n)| **n >= quorum && **n <= num.get()) {
            transactions += trxs.len();
            continue;
        }
        for ((r, trxs), k) in map {
            eprintln!(
                "{r}: {:?} = {k}",
                trxs.into_iter().map(|t| t.to_string()).collect::<Vec<_>>()
            )
        }
        panic!("outputs do not match")
    }

    finish.cancel();
}
