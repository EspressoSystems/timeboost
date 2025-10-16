use anyhow::{Result, bail};
use futures::FutureExt;
use reqwest::Url;
use std::time::{Duration, Instant};
use timeboost_types::sailfish::RoundNumber;
use tokio::time::sleep;
use tokio::{select, signal};
use tracing::{error, info};

const ROUND_TIMEOUT_SECS: u64 = 30;
const MAX_ROUND_TIMEOUTS: u64 = 15;

#[derive(Debug)]
pub struct Until {
    rounds: RoundNumber,
    duration: Duration,
    host: Url,
    require_decrypted: Option<RoundNumber>,
}

impl Until {
    pub fn new<N>(r: N, d: Duration, host: Url) -> Self
    where
        N: Into<RoundNumber>,
    {
        Self {
            rounds: r.into(),
            duration: d,
            host,
            require_decrypted: None,
        }
    }

    pub fn require_decrypted<N>(&mut self, rounds: Option<N>) -> &mut Self
    where
        N: Into<RoundNumber>,
    {
        self.require_decrypted = rounds.map(|r| r.into());
        self
    }

    pub async fn run(self) -> Result<()> {
        let mut timer = sleep(self.duration).fuse().boxed();

        let mut req_timer = sleep(Duration::from_secs(1)).fuse().boxed();

        let mut last_committed = 0;
        let mut last_committed_time = Instant::now();

        loop {
            select! {
                _ = &mut timer => {
                    error!("watchdog timed out, shutting down");
                    bail!("watchdog timeout")
                }
                _ = &mut req_timer => {
                    req_timer = sleep(Duration::from_secs(1)).fuse().boxed();
                    if let Ok(resp) = reqwest::get(self.host.join("i/metrics").expect("valid url")).await {
                        if let Ok(text) = resp.text().await {
                            let committed_round = text
                                .lines()
                                .find(|line| line.starts_with("committed_round"))
                                .and_then(|line| line.split(' ').nth(1))
                                .and_then(|num| num.parse::<u64>().ok())
                                .unwrap_or(0);

                            if committed_round > 0 && committed_round % 10 == 0 {
                                info!(%committed_round);
                            }

                            let now = Instant::now();

                            if committed_round == last_committed
                                && now.saturating_duration_since(last_committed_time) > Duration::from_secs(ROUND_TIMEOUT_SECS)
                            {
                                bail!("node stuck on round for more than {} seconds", ROUND_TIMEOUT_SECS)
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
                                bail!("node timed out too many rounds")
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

                            if committed_round >= *self.rounds {
                                if let Some(r) = self.require_decrypted {
                                    if output_decrypted > *r {
                                        info!(
                                            %committed_round,
                                            %queued_encrypted,
                                            %output_decrypted,
                                            "watchdog completed successfully"
                                        );
                                        break;
                                    }
                                    info!(%committed_round, %queued_encrypted, %output_decrypted);
                                } else {
                                    info!(%committed_round, "watchdog completed successfully");
                                    break;
                                }
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
}
