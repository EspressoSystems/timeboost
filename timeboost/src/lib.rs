mod config;

use std::future::pending;
use std::iter::once;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use api::metrics::serve_metrics_api;
use metrics::TimeboostMetrics;
use multisig::PublicKey;
use reqwest::Url;
use timeboost_builder::{Certifier, CertifierDown, Submitter};
use timeboost_proto::internal::internal_api_server::InternalApiServer;
use timeboost_sequencer::{Output, Sequencer};
use timeboost_types::{BundleVariant, CertifiedBlock};
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::net::lookup_host;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::task::spawn;
use tracing::{error, info, instrument, warn};
use vbs::version::StaticVersion;

pub use config::{TimeboostConfig, TimeboostConfigBuilder};
pub use timeboost_builder as builder;
pub use timeboost_crypto as crypto;
pub use timeboost_proto as proto;
pub use timeboost_sequencer as sequencer;
pub use timeboost_types as types;

use crate::api::internal::InternalApiService;
use crate::forwarder::nitro_forwarder::NitroForwarder;

pub mod api;
pub mod forwarder;
pub mod metrics;

pub struct Timeboost {
    label: PublicKey,
    receiver: Receiver<BundleVariant>,
    sequencer: Sequencer,
    certifier: Certifier,
    _metrics: Arc<TimeboostMetrics>,
    nitro_forwarder: Option<NitroForwarder>,
    metrics_task: JoinHandle<()>,
    internal_api: JoinHandle<Result<(), tonic::transport::Error>>,
    submitter_task: JoinHandle<()>,
    submit_queue: mpsc::UnboundedSender<CertifiedBlock>,
}

impl Drop for Timeboost {
    fn drop(&mut self) {
        self.metrics_task.abort();
        self.internal_api.abort();
        self.submitter_task.abort();
    }
}

impl Timeboost {
    pub async fn new(cfg: TimeboostConfig, rx: Receiver<BundleVariant>) -> Result<Self> {
        let pro = Arc::new(PrometheusMetrics::default());
        let met = Arc::new(TimeboostMetrics::new(&*pro));
        let seq = Sequencer::new(cfg.sequencer_config(), &*pro).await?;
        let blk = Certifier::new(cfg.certifier_config(), &*pro).await?;

        // TODO: Once we have e2e listener this check wont be needed
        let nitro_forwarder = if let Some(nitro_addr) = cfg.nitro_addr.clone() {
            Some(NitroForwarder::connect(cfg.sign_keypair.public_key(), nitro_addr).await?)
        } else {
            None
        };

        let internal_api = {
            let Some(addr) = lookup_host(cfg.internal_api.to_string()).await?.next() else {
                bail!("{} does not resolve to a socket address", cfg.internal_api)
            };
            let svc = InternalApiService::new(cfg.sign_keypair.public_key(), blk.handle());
            tonic::transport::Server::builder()
                .add_service(InternalApiServer::new(svc))
                .serve(addr)
        };

        let mut submitter = Submitter::new(cfg.submitter_config()).init().await;
        let (submit_tx, mut submit_rx) = mpsc::unbounded_channel();

        Ok(Self {
            metrics_task: spawn(metrics_api(pro.clone(), cfg.metrics_port)),
            label: cfg.sign_keypair.public_key(),
            receiver: rx,
            sequencer: seq,
            certifier: blk,
            _metrics: met,
            nitro_forwarder,
            internal_api: spawn(internal_api),
            submitter_task: spawn(async move {
                while let Some(cb) = submit_rx.recv().await {
                    submitter.submit(&cb).await
                }
            }),
            submit_queue: submit_tx,
        })
    }

    /// Run the timeboost app
    #[instrument(level = "info", skip_all)]
    pub async fn go(mut self) -> Result<()> {
        loop {
            select! {
                trx = self.receiver.recv() => {
                    if let Some(t) = trx {
                        self.sequencer.add_bundles(once(t))
                    }
                },
                out = self.sequencer.next() => match out {
                    Ok(Output::Transactions { round, timestamp, transactions }) => {
                        info!(
                            node  = %self.label,
                            round = %round,
                            trxs  = %transactions.len(),
                            "sequencer output"
                        );
                        if let Some(ref mut f) = self.nitro_forwarder {
                            f.enqueue(round, timestamp, &transactions).await?;
                        }
                        else {
                            warn!(node = %self.label, %round, "no forwarder => dropping output")
                        }
                    }
                    Ok(Output::UseCommittee(r)) => {
                        if let Err(e) = self.certifier.use_committee(r).await {
                            let e: CertifierDown = e;
                            return Err(e.into())
                        }
                    }
                    Err(err) => {
                        return Err(err.into())
                    }
                },
                blk = self.certifier.next_block() => match blk {
                    Ok(b) => {
                        info!(node = %self.label, block = %b.data().round(), "certified block");
                        if self.submit_queue.send(b).is_err() {
                            error!(node = %self.label, "submit task terminated");
                            return Err(anyhow!("submit task terminated"))
                        }
                    }
                    Err(e) => {
                        let e: CertifierDown = e;
                        return Err(e.into())
                    }
                },
                int = &mut self.internal_api => {
                    match int {
                        Ok(Ok(()))   => error!(node = %self.label, "internal api terminated"),
                        Ok(Err(err)) => error!(node = %self.label, %err, "internal api error"),
                        Err(err)     => error!(node = %self.label, %err, "internal api panic")
                    }
                    return Err(anyhow!("internal api not available"))
                },
                met = &mut self.metrics_task => {
                    match met {
                        Ok(())   => warn!(node = %self.label, "metrics api terminated"),
                        Err(err) => warn!(node = %self.label, %err, "metrics api panic")
                    }
                    // A terminating metrics task is not considered critical, i.e.
                    // Timeboost keeps running. However we must not poll the existing
                    // metrics_task join handle after it completed, therefore we
                    // reset it to a never-ending task:
                    self.metrics_task = spawn(pending())
                }
            }
        }
    }
}

pub async fn metrics_api(metrics: Arc<PrometheusMetrics>, metrics_port: u16) {
    serve_metrics_api::<StaticVersion<0, 1>>(metrics_port, metrics).await
}

pub async fn rpc_api(sender: Sender<BundleVariant>, rpc_port: u16) {
    if let Err(e) = api::endpoints::TimeboostApiState::new(sender)
        .run(Url::parse(&format!("http://0.0.0.0:{rpc_port}")).unwrap())
        .await
    {
        error!("failed to run timeboost api: {}", e);
    }
}
