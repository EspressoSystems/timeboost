mod conf;
mod metrics;

use std::env;
use std::sync::Arc;

use ::metrics::prometheus::PrometheusMetrics;
use anyhow::{Result, bail};
use futures::stream::BoxStream;
use futures::{Stream, StreamExt};
use multisig::PublicKey;
use timeboost_builder::{Certifier, CertifierDown, SenderTaskDown, Submitter};
use timeboost_config::CommitteeConfig;
use timeboost_sequencer::{Output, Sequencer};
use timeboost_types::{BundleVariant, ConsensusTime};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info, warn};

pub use cliquenet as net;
pub use conf::{TimeboostConfig, TimeboostConfigBuilder};
pub use multisig;
pub use timeboost_builder as builder;
pub use timeboost_config as config;
pub use timeboost_crypto as crypto;
pub use timeboost_proto as proto;
pub use timeboost_sequencer as sequencer;
pub use timeboost_types as types;

use crate::api::ApiServer;
use crate::api::internal::GrpcServer;
use crate::forwarder::nitro_forwarder::NitroForwarder;
use crate::metrics::TimeboostMetrics;

pub mod api;
pub mod forwarder;

pub(crate) const TIMEBOOST_NO_SUBMIT: &str = "TIMEBOOST_NO_SUBMIT";

pub struct Timeboost {
    label: PublicKey,
    config: TimeboostConfig,
    sender: Sender<BundleVariant>,
    receiver: Receiver<BundleVariant>,
    sequencer: Sequencer,
    certifier: Certifier,
    prometheus: Arc<PrometheusMetrics>,
    nitro_forwarder: NitroForwarder,
    submitter: Submitter,
    committees: BoxStream<'static, CommitteeConfig>,
    metrics: TimeboostMetrics,
}

impl Timeboost {
    pub async fn new<S>(cfg: TimeboostConfig, stream: S) -> Result<Self>
    where
        S: Stream<Item = CommitteeConfig> + Send + 'static,
    {
        let pro = Arc::new(PrometheusMetrics::default());
        let seq = Sequencer::new(cfg.sequencer_config(), &*pro).await?;
        let blk = Certifier::new(cfg.certifier_config(), &*pro).await?;
        let sub = Submitter::new(cfg.submitter_config(), &*pro);
        let met = TimeboostMetrics::new(&*pro);

        let nitro_forwarder =
            NitroForwarder::new(cfg.sign_keypair.public_key(), cfg.nitro_addr.clone())?;

        let (tx, rx) = mpsc::channel(100);

        Ok(Self {
            label: cfg.sign_keypair.public_key(),
            config: cfg,
            sender: tx,
            receiver: rx,
            sequencer: seq,
            certifier: blk,
            prometheus: pro,
            nitro_forwarder,
            submitter: sub,
            committees: stream.boxed(),
            metrics: met,
        })
    }

    pub fn api(&self) -> ApiServer {
        ApiServer::builder()
            .bundles(self.sender.clone())
            .enc_key(self.config.threshold_dec_key.clone())
            .metrics(self.prometheus.clone())
            .build()
    }

    pub fn internal_grpc_api(&self) -> GrpcServer {
        GrpcServer::new(self.certifier.handle())
    }

    pub async fn go(mut self) -> Result<()> {
        let no_submit = env::var(TIMEBOOST_NO_SUBMIT).is_ok();

        loop {
            select! {
                trx = self.receiver.recv() => {
                    if let Some(t) = trx {
                        self.sequencer.add_bundle(t).await?
                    }
                },
                out = self.sequencer.next() => match out {
                    Ok(Output::Transactions { round, timestamp, transactions, delayed_inbox_index }) => {
                        info!(node = %self.label, %round, trxs = %transactions.len(), "sequencer output");
                        self.metrics.update(round);
                        self.nitro_forwarder
                            .enqueue(round, timestamp, &transactions, delayed_inbox_index).await?
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
                        if no_submit {
                            warn!(
                                node  = %self.label,
                                block = %b.data().round(),
                                "TIMEBOOST_NO_SUBMIT is set, not submitting block"
                            );
                        } else if let Err(e) = self.submitter.submit(b).await {
                            let e: SenderTaskDown = e;
                            return Err(e.into())
                        }
                    }
                    Err(e) => {
                        let e: CertifierDown = e;
                        return Err(e.into())
                    }
                },
                res = self.committees.next() => match res {
                    Some(committee) => {
                        info!(node = %self.label, committee = %committee.id, "new committee config");
                        let time = ConsensusTime(committee.effective);
                        let comm = committee.sailfish();
                        let store = committee.dkg_key_store();
                        self.sequencer.set_next_committee(time, comm.clone(), store).await?;
                        self.certifier.set_next_committee(comm).await?
                    }
                    None => {
                        error!(node = %self.label, "committee config stream ended");
                        bail!("end of committee config stream")
                    }
                }
            }
        }
    }
}
