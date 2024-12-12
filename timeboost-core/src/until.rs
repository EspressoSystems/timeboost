use tokio::sync::watch;

pub async fn run_until(
    port: u16,
    until: u64,
    timeout: u64,
    is_docker: bool,
    shutdown_tx: watch::Sender<()>,
) {
    use futures::FutureExt;
    use tokio::time::sleep;

    sleep(std::time::Duration::from_secs(1)).await;

    let mut timer = sleep(std::time::Duration::from_secs(timeout))
        .fuse()
        .boxed();

    let host = if is_docker { "172.20.0.2" } else { "localhost" };

    // Deliberately run this on a timeout to avoid a runaway testing scenario.
    loop {
        tokio::select! {
            _ = &mut timer => {
                tracing::error!("watchdog timed out, shutting down");
                shutdown_tx.send(()).expect(
                    "the shutdown sender was dropped before the receiver could receive the token",
                );
                return;
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

                        if committed_round >= until {
                            tracing::info!("watchdog completed successfully");
                            shutdown_tx.send(()).expect(
                                    "the shutdown sender was dropped before the receiver could receive the token",
                                );
                            return;
                        }
                    }
                }
            }
        }
    }
}
