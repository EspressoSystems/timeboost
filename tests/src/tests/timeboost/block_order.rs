use std::iter::once;
use std::num::NonZeroUsize;
use std::time::Duration;

use bytes::Bytes;
use metrics::NoMetrics;
use multisig::Certificate;
use timeboost_builder::Certifier;
use timeboost_sequencer::{Output, Sequencer};
use timeboost_types::{Block, BlockInfo};
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::{gen_bundles, make_configs};

const NUM_OF_BLOCKS: usize = 50;
const RECOVER_INDEX: usize = 2;

#[tokio::test]
async fn block_order() {
    init_logging();

    let num = NonZeroUsize::new(5).unwrap();
    let (enc_keys, cfg) = make_configs(num, RECOVER_INDEX);

    let mut rxs = Vec::new();
    let mut tasks = JoinSet::new();
    let (bcast, _) = broadcast::channel(3);
    let finish = CancellationToken::new();

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
            let mut p = Certifier::new(b, &NoMetrics).await.unwrap();
            loop {
                select! {
                    t = brx.recv() => match t {
                        Ok(trx) => s.add_bundles(once(trx)),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(err) => panic!("{err}")
                    },
                    o = s.next() => {
                        let Output::Transactions { round, .. } = o.unwrap() else {
                            continue
                        };
                        let b = Block::new(*round, Bytes::new());
                        p.handle().enqueue(b).await.unwrap()
                    }
                    b = p.next_block() => {
                        let b = b.expect("block");
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
        rxs.push(rx)
    }

    for enc_key in &enc_keys {
        enc_key.read().await;
    }

    tasks.spawn(gen_bundles(enc_keys[0].clone(), bcast.clone()));

    // Collect all outputs:
    let mut outputs: Vec<Vec<BlockInfo>> = vec![Vec::new(); num.get()];
    for _ in 0..NUM_OF_BLOCKS {
        for (i, o) in outputs.iter_mut().enumerate() {
            let x = rxs[i].recv().await.unwrap();
            o.push(x);
        }
    }

    finish.cancel();

    // Compare outputs:
    for (a, b) in outputs.iter().zip(outputs.iter().skip(1)) {
        if a != b {
            for infos in &outputs {
                let xy = infos
                    .iter()
                    .map(|i| (*i.num(), *i.round()))
                    .collect::<Vec<_>>();
                eprintln!("{xy:?}")
            }
            panic!("outputs do not match")
        }
    }
}
