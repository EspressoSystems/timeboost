use std::process::exit;
use std::time::Duration;

use alloy::transports::http::reqwest;
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use futures::FutureExt;
use tokio::{
    pin,
    process::Command,
    select, signal,
    time::{Instant, interval, sleep},
};
use tracing::{debug, error, info, warn};
use url::Url;

const ROUND_TIMEOUT_SECS: u64 = 30;
const MAX_ROUND_TIMEOUTS: u64 = 15;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    api: Url,

    #[clap(long)]
    timeout: u64,

    #[clap(long)]
    sailfish_rounds: u64,

    #[clap(long)]
    decrypt_rounds: Option<u64>,

    cmd: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let metrics_url = args.api.join("i/metrics").context("valid url")?;

    let mut process = {
        let mut cmdline = args.cmd.into_iter();
        let exe = cmdline.next().ok_or_else(|| anyhow!("invalid cmd"))?;
        let mut cmd = Command::new(exe);
        cmd.args(cmdline).kill_on_drop(true);
        cmd.spawn()?
    };

    let process_future = process.wait();
    pin!(process_future);

    let mut timer = sleep(Duration::from_secs(args.timeout)).fuse().boxed();
    let mut interval = interval(Duration::from_secs(1));

    let mut last_committed = 0;
    let mut last_committed_time = Instant::now();

    loop {
        select! {
            r = &mut process_future => {
                match r {
                    Ok(status) => warn!(%status, "child process exited"),
                    Err(err)   => warn!(%err, "child process exited")
                }
                exit(1)
            },
            _ = &mut timer => {
                error!("watchdog timed out, shutting down");
                exit(2)
            }
            _ = interval.tick() => {
                match reqwest::get(metrics_url.clone()).await {
                    Ok(resp) => {
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

                            debug!(%committed_round, %queued_encrypted, %output_decrypted);

                            if committed_round >= args.sailfish_rounds {
                                if let Some(r) = args.decrypt_rounds {
                                    if output_decrypted > r {
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
                    Err(err) => {
                        warn!(%err, "failed to get metrics")
                    }
                }
            }
            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                break;
            }
        }
    }

    Ok(())
}
