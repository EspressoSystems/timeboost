mod conf;

use std::iter::once;
use std::sync::Arc;

use ::metrics::prometheus::PrometheusMetrics;
use anyhow::{Result, anyhow};
use committee::NewCommitteeStream;
use futures::StreamExt;
use metrics::TimeboostMetrics;
use multisig::PublicKey;
use timeboost_builder::{Certifier, CertifierDown, SenderTaskDown, Submitter};
use timeboost_contract::provider::PubSubProvider;
use timeboost_sequencer::{Output, Sequencer};
use timeboost_types::{BundleVariant, ConsensusTime};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{info, warn};

pub use conf::{TimeboostConfig, TimeboostConfigBuilder};
pub use timeboost_builder as builder;
pub use timeboost_config as config;
pub use timeboost_crypto as crypto;
pub use timeboost_proto as proto;
pub use timeboost_sequencer as sequencer;
pub use timeboost_types as types;

use crate::api::ApiServer;
use crate::api::internal::GrpcServer;
use crate::committee::CommitteeInfo;
use crate::forwarder::nitro_forwarder::NitroForwarder;

pub mod api;
pub mod committee;
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
    // pubsub service (+backend) handle, disconnect on drop
    _pubsub_provider: PubSubProvider,
    events: NewCommitteeStream,
    #[cfg(feature = "times")]
    epoch: std::time::Instant,
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

        let provider = PubSubProvider::new(cfg.chain_config.parent.ws_url.clone()).await?;
        let events = CommitteeInfo::new_committee_stream(
            &provider,
            cfg.registered_blk.into(),
            &cfg.chain_config.parent,
        )
        .await?;

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
            _pubsub_provider: provider,
            events,
            #[cfg(feature = "times")]
            epoch: std::time::Instant::now(),
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
        #[cfg(feature = "times")]
        let mut dumped = false;

        #[cfg(feature = "times")]
        {
            self.epoch = std::time::Instant::now();
        }

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
                        #[cfg(feature = "times")]
                        {
                            if *round % 100 == 0 {
                                info!(target: "times", node = %self.label, round = %*round)
                            }
                            if !dumped && *round >= self.config.times_until {
                                self.save_durations().await?;
                                dumped = true
                            }
                        }
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
                        if let Err(e) = self.submitter.submit(b).await {
                            let e: SenderTaskDown = e;
                            return Err(e.into())
                        }
                    }
                    Err(e) => {
                        let e: CertifierDown = e;
                        return Err(e.into())
                    }
                },
                res = self.events.next() => match res {
                    Some(comm_info) => {
                        let cur = self.config.key_store.committee().id();
                        let new_id = comm_info.id();

                        // contract ensures consecutive CommitteeId assignment
                        if new_id == cur + 1 {
                            info!(node = %self.label, committee_id = %new_id, current = %cur, "setting next committee");
                            self.sequencer.set_next_committee(
                                ConsensusTime(comm_info.effective_timestamp()),
                                comm_info.sailfish_committee(),
                                comm_info.dkg_key_store()
                            ).await?;
                        } else {
                            warn!(node = %self.label, committee_id = %new_id, current = %cur, "ignored new CommitteeCreated event");
                            continue;
                        }
                    },
                    None => {
                        warn!(node = %self.label, "event subscription stream ended");
                        return Err(anyhow!("contract event pubsub service prematurely shutdown"));
                    }
                }
            }
        }
    }

    /// Save the durations of various phases.
    #[cfg(feature = "times")]
    async fn save_durations(&self) -> Result<()> {
        let Some(sf_start) = times::time_series("sf-round-start") else {
            anyhow::bail!("no time series corresponds to sf-round-start")
        };
        let Some(sf_end) = times::time_series("sf-round-end") else {
            anyhow::bail!("no time series corresponds to sf-round-end")
        };
        let Some(tb_decrypt_start) = times::time_series("tb-decrypt-start") else {
            anyhow::bail!("no time series corresponds to tb-decrypt-start")
        };
        let Some(tb_decrypt_end) = times::time_series("tb-decrypt-end") else {
            anyhow::bail!("no time series corresponds to tb-decrypt-end")
        };
        let Some(tb_cert_start) = times::time_series("tb-certify-start") else {
            anyhow::bail!("no time series corresponds to tb-certify-start")
        };
        let Some(tb_cert_end) = times::time_series("tb-certify-end") else {
            anyhow::bail!("no time series corresponds to tb-certify-end")
        };
        let mut csv = csv::Writer::from_writer(Vec::new());
        for (r, sfs) in sf_start.records() {
            let Some(sfe) = sf_end.records().get(r) else {
                continue;
            };
            let Some(tbds) = tb_decrypt_start.records().get(r) else {
                continue;
            };
            let Some(tbde) = tb_decrypt_end.records().get(r) else {
                continue;
            };
            let Some(tbcs) = tb_cert_start.records().get(r) else {
                continue;
            };
            let Some(tbce) = tb_cert_end.records().get(r) else {
                continue;
            };
            csv.serialize(Durations {
                round: *r,
                sailfish: sfe.duration_since(*sfs).as_millis() as u64,
                decrypt: tbde.duration_since(*tbds).as_millis() as u64,
                certify: tbce.duration_since(*tbcs).as_millis() as u64,
                total: tbce.duration_since(*sfs).as_millis() as u64,
            })?
        }
        let path = std::path::Path::new("/tmp")
            .join(self.label.to_string())
            .with_extension("csv");
        tokio::fs::write(path, csv.into_inner()?).await?;
        Ok(())
    }
}

#[cfg(feature = "times")]
#[derive(serde::Serialize)]
struct Durations {
    round: u64,
    sailfish: u64,
    decrypt: u64,
    certify: u64,
    total: u64,
}
