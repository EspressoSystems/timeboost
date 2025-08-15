mod config;

use std::iter::once;
use std::sync::Arc;

use anyhow::Result;
use metrics::TimeboostMetrics;
use multisig::PublicKey;
use timeboost_builder::{Certifier, CertifierDown, Submitter};
use timeboost_sequencer::{Output, Sequencer};
use timeboost_types::BundleVariant;
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{info, warn};

pub use config::{TimeboostConfig, TimeboostConfigBuilder};
pub use timeboost_builder as builder;
pub use timeboost_crypto as crypto;
pub use timeboost_proto as proto;
pub use timeboost_sequencer as sequencer;
pub use timeboost_types as types;

use crate::api::ApiServer;
use crate::api::internal::GrpcServer;
use crate::forwarder::nitro_forwarder::NitroForwarder;

pub mod api;
pub mod forwarder;
pub mod metrics;

pub struct Timeboost {
    label: PublicKey,
    config: TimeboostConfig,
    sender: Sender<BundleVariant>,
    receiver: Receiver<BundleVariant>,
    sequencer: Sequencer,
    certifier: Certifier,
    _metrics: Arc<TimeboostMetrics>,
    prometheus: Arc<PrometheusMetrics>,
    nitro_forwarder: Option<NitroForwarder>,
    submitter: Submitter,
}

impl Timeboost {
    pub async fn new(cfg: TimeboostConfig) -> Result<Self> {
        let pro = Arc::new(PrometheusMetrics::default());
        let met = Arc::new(TimeboostMetrics::new(&*pro));
        let seq = Sequencer::new(cfg.sequencer_config(), &*pro).await?;
        let blk = Certifier::new(cfg.certifier_config(), &*pro).await?;
        let sub = Submitter::new(cfg.submitter_config(), &*pro);

        // TODO: Once we have e2e listener this check wont be needed
        let nitro_forwarder = if let Some(nitro_addr) = cfg.nitro_addr.clone() {
            Some(NitroForwarder::connect(cfg.sign_keypair.public_key(), nitro_addr).await?)
        } else {
            None
        };

        let (tx, rx) = mpsc::channel(100);

        Ok(Self {
            label: cfg.sign_keypair.public_key(),
            config: cfg,
            sender: tx,
            receiver: rx,
            sequencer: seq,
            certifier: blk,
            prometheus: pro,
            _metrics: met,
            nitro_forwarder,
            submitter: sub,
        })
    }

    pub fn api(&self) -> ApiServer {
        ApiServer::builder()
            .bundles(self.sender.clone())
            .enc_key(self.config.threshold_enc_key.clone())
            .metrics(self.prometheus.clone())
            .build()
    }

    pub fn internal_grpc_api(&self) -> GrpcServer {
        GrpcServer::new(self.certifier.handle())
    }

    pub async fn go(mut self) -> Result<()> {
        loop {
            select! {
                trx = self.receiver.recv() => {
                    if let Some(t) = trx {
                        self.sequencer.add_bundles(once(t))
                    }
                },
                out = self.sequencer.next() => match out {
                    Ok(Output::Transactions { round, timestamp, transactions, delayed_inbox_index }) => {
                        info!(
                            node  = %self.label,
                            round = %round,
                            trxs  = %transactions.len(),
                            "sequencer output"
                        );
                        if let Some(ref mut f) = self.nitro_forwarder {
                            f.enqueue(round, timestamp, &transactions, delayed_inbox_index).await?;
                        } else {
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
                        self.submitter.submit(b).await
                    }
                    Err(e) => {
                        let e: CertifierDown = e;
                        return Err(e.into())
                    }
                }
            }
        }
    }
}
