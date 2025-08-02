use anyhow::Result;
use std::time::{Duration, Instant};
use tokio::signal;

const ROUND_TIMEOUT_SECS: u64 = 30;
const MAX_ROUND_TIMEOUTS: u64 = 15;

pub async fn run_until(until: u64, timeout: u64, host: reqwest::Url) -> Result<()> {
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
                anyhow::bail!("Watchdog timeout")
            }
            _ = &mut req_timer => {
                req_timer = sleep(Duration::from_secs(1)).fuse().boxed();
                if let Ok(resp) = reqwest::get(host.join("v0/status/metrics").expect("valid url")).await {
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
                            anyhow::bail!("Node timed out too many rounds")
                        }

                        let queued_encrypted = text
                            .lines()
                            .find(|line| line.starts_with("queued_encrypted_ilist"))
                            .and_then(|line| line.split(' ').nth(1))
                            .and_then(|num| num.parse::<u64>().ok())
                            .unwrap_or(0);
                        let output_decrypted = text
                            .lines()
                            .find(|line| line.starts_with("output_decrypted_ilist"))
                            .and_then(|line| line.split(' ').nth(1))
                            .and_then(|num| num.parse::<u64>().ok())
                            .unwrap_or(0);

                        if committed_round >= until && output_decrypted > 0 {
                            tracing::info!("committed_round: {}", committed_round);
                            tracing::info!("enqueued encrypted: {}, output decrypted: {}", queued_encrypted, output_decrypted);
                            tracing::info!("watchdog completed successfully");
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
