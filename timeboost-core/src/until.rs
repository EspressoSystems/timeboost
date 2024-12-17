use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::{signal, sync::watch};
// TODO: Reduce when we remove libp2p
const ROUND_TIMEOUT_SECS: u64 = 70;
const MAX_ROUND_TIMEOUTS: u64 = 15;
const API_REQUEST_TIMER_SECS: u64 = 1;
const API_REQUEST_TIMEOUT_MILLIS: u64 = 850;

pub async fn run_until(
    port: u16,
    until: u64,
    timeout: u64,
    is_docker: bool,
    shutdown_tx: watch::Sender<()>,
) -> Result<()> {
    use futures::FutureExt;
    use tokio::time::sleep;

    sleep(Duration::from_secs(1)).await;

    let mut timer = sleep(Duration::from_secs(timeout)).fuse().boxed();

    let mut req_timer = sleep(Duration::from_secs(API_REQUEST_TIMER_SECS))
        .fuse()
        .boxed();

    let host = if is_docker { "172.20.0.2" } else { "localhost" };

    let mut last_committed = 0;
    let mut last_committed_time = Instant::now();
    // Deliberately run this on a timeout to avoid a runaway testing scenario.
    loop {
        tokio::select! {
            _ = &mut timer => {
                tracing::error!("watchdog timed out, shutting down");
                shutdown_tx.send(()).expect(
                    "the shutdown sender was dropped before the receiver could receive the token",
                );
                anyhow::bail!("Watchdog timeout")
            }
            _ = &mut req_timer => {
                req_timer = sleep(Duration::from_secs(API_REQUEST_TIMER_SECS)).fuse().boxed();
                match tokio::time::timeout(
                    Duration::from_millis(API_REQUEST_TIMEOUT_MILLIS),
                    async move {
                        reqwest::get(format!("http://{host}:{port}/status/metrics")).await
                    }).await {
                        Ok(Ok(resp)) => {
                            if let Ok(text) = resp.text().await {
                                let committed_round = text
                                    .lines()
                                    .find(|line| line.starts_with("committed_round"))
                                    .and_then(|line| line.split(' ').nth(1))
                                    .and_then(|num| num.parse::<u64>().ok())
                                    .unwrap_or(0);

                                let now = Instant::now();
                                if committed_round == last_committed
                                    && now.saturating_duration_since(last_committed_time) > Duration::from_secs(ROUND_TIMEOUT_SECS)
                                {
                                    shutdown_tx
                                        .send(())
                                        .expect("the shutdown sender was dropped before the receiver could receive the token");
                                    anyhow::bail!("Node stuck on round for more than {} seconds", ROUND_TIMEOUT_SECS)
                                } else if committed_round > last_committed {
                                    tracing::info!("committed_round: {}", committed_round);
                                    last_committed = committed_round;
                                    last_committed_time = now;
                                }

                                let timeouts = text
                                    .lines()
                                    .find(|line| line.starts_with("rounds_timed_out"))
                                    .and_then(|line| line.split(' ').nth(1))
                                    .and_then(|num| num.parse::<u64>().ok())
                                    .unwrap_or(0);

                                if timeouts >= MAX_ROUND_TIMEOUTS {
                                    shutdown_tx.send(()).expect(
                                        "the shutdown sender was dropped before the receiver could receive the token",
                                    );
                                    anyhow::bail!("Node timed out too many rounds")
                                }

                                if committed_round >= until {
                                    tracing::info!("watchdog completed successfully");
                                    // Make sure not to shutdown right away in case other nodes needs messages still
                                    sleep(Duration::from_secs(5)).await;
                                    shutdown_tx.send(()).expect(
                                            "the shutdown sender was dropped before the receiver could receive the token",
                                        );
                                    break;
                                }
                            }
                        }
                        Ok(Err(_)) => {
                            tracing::warn!("Metrics API request failed. Port: {}", port);
                        }
                        Err(_) => {
                            tracing::warn!("Metrics API request timed out. Port {}", port);
                        }
                }
            }
            _ = signal::ctrl_c() => {
                tracing::info!("ctrl-c received, shutting down");
                break;
            }
        }
    }
    Ok(())
}
