use clap::Parser;
use futures::FutureExt;
use reqwest::Client;
use timeboost_core::load_generation::make_tx;
use timeboost_utils::types::logging;
use tokio::{signal, spawn, sync::watch, time::sleep};
use tracing::debug;

#[cfg(feature = "until")]
use timeboost_core::until::run_until;

#[derive(Parser, Debug)]
struct Cli {
    /// How oftern to generate a transaction.
    #[clap(long, default_value = "1000")]
    interval_ms: u64,

    /// The contract endpoint to fetch the current keyset
    #[clap(long, default_value = "http://localhost:7200")]
    startup_url: reqwest::Url,

    /// The until value to use for the committee config.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 1000)]
    until: u64,

    /// The watchdog timeout.
    #[cfg(feature = "until")]
    #[clap(long, default_value_t = 30)]
    watchdog_timeout: u64,
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
        let com_map = timeboost::contracts::initializer::wait_for_committee(cli.startup_url)
            .await
            .expect("failed to wait for the committee");

        let mut hosts = com_map
            .into_iter()
            .map(|c| c.1)
            .map(|url_str| format!("http://{url_str}").parse::<reqwest::Url>().unwrap())
            .collect::<Vec<_>>();

        // HACK: Our local port scheme is always 800 + SAILFISH_PORT
        hosts
            .iter_mut()
            .for_each(|h| h.set_port(Some(h.port().unwrap() + 800)).unwrap());

        hosts
    };

    debug!(
        "hostlist {}",
        hosts
            .iter()
            .map(|h| format!("{h}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Generate a transaction every interval.
    let mut timer = sleep(std::time::Duration::from_millis(cli.interval_ms))
        .fuse()
        .boxed();

    let (shutdown_tx, mut shutdown_rx) = watch::channel(());

    let client = Box::leak(Box::new(Client::new()));

    #[cfg(feature = "until")]
    {
        let mut host = hosts[0].clone();

        // HACK: Submit port is 800 + SAILFISH_PORT, metrics is 200 more than that...
        host.set_port(Some(host.port().unwrap() + 200)).unwrap();
        tokio::spawn(run_until(
            cli.until,
            cli.watchdog_timeout,
            host,
            shutdown_tx.clone(),
        ));
    }

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
