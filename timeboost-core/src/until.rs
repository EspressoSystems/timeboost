use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::{signal, sync::watch};
const ROUND_TIMEOUT_SECS: u64 = 30;
const MAX_ROUND_TIMEOUTS: u64 = 15;

pub async fn run_until(
    until: u64,
    timeout: u64,
    host: reqwest::Url,
    shutdown_tx: watch::Sender<()>,
) -> Result<()> {
    use futures::FutureExt;
    use tokio::time::sleep;

    sleep(Duration::from_secs(1)).await;

    let mut timer = sleep(Duration::from_secs(timeout)).fuse().boxed();

    let mut req_timer = sleep(Duration::from_secs(1)).fuse().boxed();

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
                req_timer = sleep(Duration::from_secs(1)).fuse().boxed();
                if let Ok(resp) = reqwest::get(host.join("/status/metrics").expect("valid url")).await {
                    if let Ok(text) = resp.text().await {
                        let committed_round = text
                            .lines()
                            .find(|line| line.starts_with("committed_round"))
                            .and_then(|line| line.split(' ').nth(1))
                            .and_then(|num| num.parse::<u64>().ok())
                            .unwrap_or(0);

                        if committed_round > 0 && committed_round % 10 == 0 {
                            tracing::info!("committed_round: {}", committed_round);
                        }

                        let now = Instant::now();
                        if committed_round == last_committed
                            && now.saturating_duration_since(last_committed_time) > Duration::from_secs(ROUND_TIMEOUT_SECS)
                        {
                            shutdown_tx
                                .send(())
                                .expect("the shutdown sender was dropped before the receiver could receive the token");
                            anyhow::bail!("Node stuck on round for more than {} seconds", ROUND_TIMEOUT_SECS)
                        } else if committed_round > last_committed {
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
                            // Make sure we dont shut down the network too early in case other nodes need our messages
                            sleep(Duration::from_secs(5)).await;
                            tracing::info!("watchdog completed successfully");
                            shutdown_tx.send(()).expect(
                                    "the shutdown sender was dropped before the receiver could receive the token",
                                );
                            break;
                        }
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
