use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::{signal, sync::watch};
// TODO: Reduce when we remove libp2p
const ROUND_TIMEOUT_SECS: u64 = 70;
const MAX_ROUND_TIMEOUTS: u64 = 15;

pub async fn run_until(
    port: u16,
    until: u64,
    timeout: u64,
    is_docker: bool,
    shutdown_tx: watch::Sender<()>,
) -> Result<()> {
    use futures::FutureExt;
    use tokio::time::sleep;

    sleep(std::time::Duration::from_secs(1)).await;

    let mut timer = sleep(std::time::Duration::from_secs(timeout))
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
            resp = reqwest::get(format!("http://{host}:{port}/status/metrics")) => {
                if let Ok(resp) = resp {
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
                            anyhow::bail!("Node stuck on round for more than 30 seconds")
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
