mod conf;

use std::iter::once;
use std::sync::Arc;

use ::metrics::prometheus::PrometheusMetrics;
use alloy::eips::BlockNumberOrTag;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use alloy::transports::ws::WsConnect;
use anyhow::{Result, anyhow};
use cliquenet::AddressableCommittee;
use futures::StreamExt;
use metrics::TimeboostMetrics;
use multisig::{Committee, PublicKey, x25519};
use sailfish::types::Timestamp;
use timeboost_builder::{Certifier, CertifierDown, Submitter};
use timeboost_contract::CommitteeMemberSol;
use timeboost_contract::{KeyManager, KeyManager::CommitteeCreated};
use timeboost_crypto::prelude::DkgEncKey;
use timeboost_sequencer::{Output, Sequencer};
use timeboost_types::{BundleVariant, ConsensusTime, KeyStore};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info, warn};

pub use conf::{TimeboostConfig, TimeboostConfigBuilder};
pub use timeboost_builder as builder;
pub use timeboost_config as config;
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
            .enc_key(self.config.threshold_dec_key.clone())
            .metrics(self.prometheus.clone())
            .build()
    }

    pub fn internal_grpc_api(&self) -> GrpcServer {
        GrpcServer::new(self.certifier.handle())
    }

    pub async fn go(mut self) -> Result<()> {
        // setup the websocket for contract event stream
        let ws = WsConnect::new(self.config.chain_config.parent.ws_url.clone());
        // spawn the pubsub service (and backend) and the frontend is registered at the provider
        let provider = ProviderBuilder::new()
            .connect_pubsub_with(ws)
            .await
            .map_err(|err| {
                error!(?err, "event pubsub failed to start");
                err
            })?;

        let chain_id = provider.get_chain_id().await.map_err(|err| {
            error!(?err, "fail to get chainid");
            err
        })?;
        // local test chain don't have finality gadget, thus don't support `Finalized` tag
        let tag = if chain_id == 31337 || chain_id == 1337 {
            BlockNumberOrTag::Latest
        } else {
            BlockNumberOrTag::Finalized
        };
        let filter = Filter::new()
            .address(self.config.chain_config.parent.key_manager_contract)
            .event(KeyManager::CommitteeCreated::SIGNATURE)
            .from_block(tag);
        let mut events = provider
            .subscribe_logs(&filter)
            .await
            .map_err(|err| {
                error!(?err, "pubsub subscription failed");
                err
            })?
            .into_stream();

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
                },
                res = events.next() => match res {
                    Some(log) => {
                        let typed_log = log.log_decode_validate::<CommitteeCreated>()?;
                        let id = typed_log.data().id;
                        let cur: u64 = self.config.key_store.committee().id().into();

                        if id == cur + 1 {
                            info!(node = %self.label, committee_id = %id, current = %cur, "setting next committee");
                            let (t, a, k) = self.fetch_next_committee(&provider, id).await?;
                            self.sequencer.set_next_committee(t, a, k).await?;
                        } else {
                            warn!(node = %self.label, committee_id = %id, current = %cur, "ignored new CommitteeCreated event");
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

    /// Given the next committee is available on chain, fetch it and prepare it for `NextCommittee`
    async fn fetch_next_committee(
        &self,
        provider: impl Provider,
        next_committee_id: u64,
    ) -> Result<(ConsensusTime, AddressableCommittee, KeyStore)> {
        let contract = KeyManager::new(
            self.config.chain_config.parent.key_manager_contract,
            &provider,
        );
        let c = contract.getCommitteeById(next_committee_id).call().await?;
        let members: Vec<CommitteeMemberSol> = c.members;
        let timestamp: Timestamp = c.effectiveTimestamp.into();

        let sailfish_peer_hosts_and_keys = members
            .iter()
            .map(|peer| {
                let sig_key = multisig::PublicKey::try_from(peer.sigKey.as_ref())?;
                let dh_key = x25519::PublicKey::try_from(peer.dhKey.as_ref())?;
                let sailfish_address = cliquenet::Address::try_from(peer.networkAddress.as_ref())?;
                Ok((sig_key, dh_key, sailfish_address))
            })
            .collect::<Result<Vec<_>>>()?;
        let dkg_enc_keys = members
            .iter()
            .map(|peer| {
                let dkg_enc_key = DkgEncKey::from_bytes(peer.dkgKey.as_ref())?;
                Ok(dkg_enc_key)
            })
            .collect::<Result<Vec<_>>>()?;

        let sailfish_committee = {
            let c = Committee::new(
                next_committee_id,
                sailfish_peer_hosts_and_keys
                    .iter()
                    .enumerate()
                    .map(|(i, (k, ..))| (i as u8, *k)),
            );
            AddressableCommittee::new(c, sailfish_peer_hosts_and_keys.iter().cloned())
        };

        let key_store = KeyStore::new(
            sailfish_committee.committee().clone(),
            dkg_enc_keys
                .into_iter()
                .enumerate()
                .map(|(i, k)| (i as u8, k)),
        );

        Ok((ConsensusTime(timestamp), sailfish_committee, key_store))
    }
}
