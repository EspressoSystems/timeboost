use bytes::Bytes;
use clap::Parser;
use futures::FutureExt;
use rand::Rng;
use reqwest::Client;
use timeboost::contracts::committee::CommitteeBase;
use timeboost_core::types::{
    seqno::SeqNo,
    transaction::{Address, Nonce, Transaction, TransactionData},
};
use timeboost_utils::types::logging;
use tokio::{signal, spawn, sync::watch, time::sleep};
use tracing::debug;

#[cfg(feature = "until")]
use timeboost_core::until::run_until;

const SIZE_512_B: usize = 512;

#[derive(Parser, Debug)]
struct Cli {
    /// The committee size.
    #[clap(long)]
    committee_size: usize,

    /// How oftern to generate a transaction.
    #[clap(long, default_value = "5000")]
    interval_ms: u64,

    /// The contract endpoint to fetch the current keyset
    #[clap(long, default_value = "http://localhost:7200")]
    startup_url: reqwest::Url,

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The base to use for the committee config.
    #[clap(long, value_enum, default_value_t = CommitteeBase::Local)]
    base: CommitteeBase,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,
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
        // Generate some random number of transactions in the bundle
        let num_txns = rand::thread_rng().gen_range(1..1000);

        // Get the txns
        let txns = make_tx_data(num_txns, SIZE_512_B);
        Transaction::Priority {
            nonce: Nonce::now(SeqNo::from(0)),
            to: Address::zero(),
            txns,
        }
    } else {
        Transaction::Regular {
            // The index here is safe since we always generate a single txn.
            txn: make_tx_data(1, SIZE_512_B).remove(0),
        }
    }
}

/// Creates a transaction and sends it to all the nodes in the committee.
async fn create_and_send_tx(host: reqwest::Url, client: &'static Client, req_timeout_millis: u64) {
    let tx = make_tx();

    match tokio::time::timeout(
        std::time::Duration::from_millis(req_timeout_millis),
        async move {
            match client
                .post(host.join("/v0/submit").expect("valid url"))
                .json(&tx)
                .send()
                .await
            {
                Ok(resp) => {
                    tracing::debug!("resp: {:?}", resp);
                }
                Err(e) => {
                    tracing::error!("error: {:?}", e);
                }
            }
        },
    )
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
    logging::init_logging();

    let cli = Cli::parse();

    let hosts = {
        match cli.base {
            CommitteeBase::Local => (0..cli.committee_size)
                .map(|i| {
                    format!("http://localhost:{}", 8800 + i)
                        .parse::<reqwest::Url>()
                        .unwrap()
                })
                .collect::<Vec<_>>(),
            CommitteeBase::Network => {
                let (com_map, _) =
                    timeboost::contracts::initializer::wait_for_committee(cli.startup_url)
                        .await
                        .expect("failed to wait for the committee");

                let mut hosts = com_map
                    .into_values()
                    .map(|url_str| format!("http://{url_str}").parse::<reqwest::Url>().unwrap())
                    .collect::<Vec<_>>();

                // HACK: Our local port scheme is always 800 + SAILFISH_PORT
                hosts
                    .iter_mut()
                    .for_each(|h| h.set_port(Some(h.port().unwrap() + 800)).unwrap());

                hosts
            }
        }
    };

    debug!("hostlist {:?}", hosts);

    // Generate a transaction every interval.
    let mut timer = sleep(std::time::Duration::from_millis(cli.interval_ms))
        .fuse()
        .boxed();

    let (shutdown_tx, mut shutdown_rx) = watch::channel(());

    let client = Box::leak(Box::new(Client::new()));

    #[cfg(feature = "until")]
    tokio::spawn(run_until(
        cli.until,
        cli.watchdog_timeout,
        hosts[0].clone(),
        shutdown_tx.clone(),
    ));

    loop {
        tokio::select! {
            _ = &mut timer => {
                tracing::debug!("sending tx");
                timer = sleep(std::time::Duration::from_millis(cli.interval_ms)).fuse().boxed();
                // We're gonna put this in a thread so that way if there's a delay sending to any
                // node, it doesn't block the execution.
                for host in &hosts {
                    // timeout before creating new tasks
                    spawn(create_and_send_tx(host.clone(), client, 500));
                }
            }
            _ = shutdown_rx.changed() => {
                tracing::info!("shutting down tx generator");
                break;
            }
            _ = signal::ctrl_c() => {
                tracing::info!("received ctrl-c; shutting down");
                shutdown_tx.send(()).expect("the shutdown sender was dropped before the receiver could receive the token");
                break;
            }
        }
    }
}
