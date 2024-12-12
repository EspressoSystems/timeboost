use std::future::pending;

use bytes::Bytes;
use clap::Parser;
use futures::FutureExt;
use rand::Rng;
use reqwest::Client;
use timeboost_core::types::{
    seqno::SeqNo,
    transaction::{Address, Nonce, Transaction, TransactionData},
};
use tokio::{signal, task::JoinSet, time::sleep};

const SIZE_500_KB: usize = 500 * 1024;

#[derive(Parser, Debug)]
struct Cli {
    /// The committee size.
    #[clap(long)]
    committee_size: usize,

    /// How oftern to generate a transaction.
    #[clap(long, default_value = "100")]
    interval_ms: u64,

    /// If we're running in docker, we need to use the correct port.
    #[clap(long, default_value = "false")]
    docker: bool,
}

fn make_tx_data(n: usize, sz: usize) -> Vec<TransactionData> {
    // Make sz bytes of random data
    let data: Bytes = (0..sz).map(|_| rand::thread_rng().gen()).collect();

    (0..n)
        .map(|i| {
            TransactionData::new(
                Nonce::now(SeqNo::from(i as u128)),
                Address::zero(),
                data.clone(),
            )
        })
        .collect()
}

fn make_tx() -> Transaction {
    // 10% chance of being a priority tx
    if rand::thread_rng().gen_bool(0.1) {
        // Genrate some random number of transactions in the bundle
        let num_txns = rand::thread_rng().gen_range(1..1000);

        // Get the txns
        let txns = make_tx_data(num_txns, SIZE_500_KB);
        Transaction::Priority {
            nonce: Nonce::now(SeqNo::from(0)),
            to: Address::zero(),
            txns,
        }
    } else {
        Transaction::Regular {
            // The index here is safe since we always genrate a single txn.
            txn: make_tx_data(1, SIZE_500_KB).remove(0),
        }
    }
}

/// Creates a transaction and sends it to all the nodes in the committee.
async fn create_and_send_tx(i: usize, is_docker: bool, client: &'static Client) {
    let port = 8800 + i;
    let tx = make_tx();

    let host = if is_docker {
        format!("172.20.0.{}", i + 2)
    } else {
        "localhost".to_string()
    };

    match tokio::time::timeout(std::time::Duration::from_secs(1), async move {
        match client
            .post(format!(
                "http://{host}:{port}/submit",
                host = host,
                port = port
            ))
            .json(&tx)
            .send()
            .await
        {
            Ok(resp) => {
                tracing::info!("resp: {:?}", resp);
            }
            Err(e) => {
                tracing::error!("error: {:?}", e);
            }
        }
    })
    .await
    {
        Ok(_) => {
            tracing::info!("tx sent successfully");
        }
        Err(e) => {
            tracing::error!(%e, "timeout sending tx");
        }
    }
}

#[tokio::main]
async fn main() {
    timeboost_core::logging::init_logging();

    let cli = Cli::parse();
    let is_docker = cli.docker;

    // Generate a transaction every interval.
    let mut timer = sleep(std::time::Duration::from_millis(cli.interval_ms))
        .fuse()
        .boxed();

    let client = Box::leak(Box::new(Client::new()));
    let mut handles: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = &mut timer => {
                tracing::debug!("sending tx");
                timer = sleep(std::time::Duration::from_millis(cli.interval_ms)).fuse().boxed();
                // We're gonna put this in a thread so that way if there's a delay sending to any
                // node, it doesn't block the execution.
                for i in 0..cli.committee_size {
                    handles.spawn(create_and_send_tx(i, is_docker, client));
                }
            }
            handle = handles.join_next() => {
                if let Some(handle) = handle {
                    match handle {
                        Ok(_) => {
                            tracing::info!("tx sent successfully");
                        }
                        Err(e) => {
                            tracing::error!(%e, "something went wrong sending the tx");
                        }
                    }
                }
            }
            _ = signal::ctrl_c() => {
                tracing::info!("shutting down tx generator");

                // Wait for all the handles to finish, or timeout after 4 seconds.
                if let Err(e) = tokio::time::timeout(std::time::Duration::from_secs(4), handles.join_all()).await {
                    // The joinset will abort all the handles when it's dropped.
                    tracing::error!(%e, "timed out waiting for txs to finish");
                }


                break;
            }
        }
    }
}
