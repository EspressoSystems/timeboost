mod conf;

use std::env;
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

#[cfg(feature = "times")]
pub mod times;

pub(crate) const TIMEBOOST_NO_SUBMIT: &str = "TIMEBOOST_NO_SUBMIT";

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
            Some(NitroForwarder::new(cfg.sign_keypair.public_key(), nitro_addr)?)
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
        let mut writer = crate::times::TimesWriter::new(self.label);

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
                            if !writer.is_timeboost_saved() && *round >= self.config.times_until {
                                writer.save_timeboost_series().await?
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
}
