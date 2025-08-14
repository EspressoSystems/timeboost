use reqwest::{Client, Url};
use std::collections::HashMap;
use timeboost_crypto::prelude::{ThresholdEncKey, ThresholdEncKeyCell};

use tracing::warn;

async fn fetch_encryption_key(client: &Client, enckey_url: &Url) -> Option<ThresholdEncKey> {
    let response = match client.get(enckey_url.clone()).send().await {
        Ok(response) => response,
        Err(err) => {
            warn!(%err, "failed to request encryption key");
            return None;
        }
    };

    if !response.status().is_success() {
        warn!("enckey request failed with status: {}", response.status());
        return None;
    }

    match response.json::<Option<ThresholdEncKey>>().await {
        Ok(enc_key) => enc_key,
        Err(err) => {
            warn!(%err, "failed to parse encryption key response");
            None
        }
    }
}

/// helper struct to keep track of sufficient quorum of DKG keys
pub(crate) struct ThresholdEncKeyCellAccumulator {
    client: Client,
    // DKG results on individual node
    results: HashMap<Url, Option<ThresholdEncKey>>,
    // (t+1)-agreed upon encryption key
    output: ThresholdEncKeyCell,
    // threshold for the accumulator to be considered as matured / finalized
    threshold: usize,
}

impl ThresholdEncKeyCellAccumulator {
    /// give a list of TimeboostApi's endpoint to query `/enckey` status
    pub(crate) fn new(client: Client, urls: impl Iterator<Item = Url>) -> Self {
        let results: HashMap<Url, Option<ThresholdEncKey>> = urls.map(|url| (url, None)).collect();
        let output = ThresholdEncKeyCell::new();
        let threshold = results.len().div_ceil(3);
        Self {
            client,
            results,
            output,
            threshold,
        }
    }

    /// try to get the threshold encryption key, only available after a threshold of nodes
    /// finish their DKG processes.
    pub(crate) async fn enc_key(&mut self) -> &ThresholdEncKeyCell {
        // if result is already available, directly return
        if self.output.get_ref().is_some() {
            &self.output
        } else {
            // first update DKG status for yet-finished nodes
            for (url, res) in self.results.iter_mut() {
                if res.is_none() {
                    *res = fetch_encryption_key(&self.client, url).await;
                }
            }

            // count for each unique enc key from DKG results of different nodes
            let mut counts: HashMap<ThresholdEncKey, usize> = HashMap::new();
            for v in self.results.values().flatten() {
                *counts.entry(v.to_owned()).or_insert(0) += 1;
            }

            // (t+1)-agreed enc_key is the output
            for (v, c) in counts.iter() {
                if *c >= self.threshold {
                    self.output.set(v.to_owned());
                }
            }
            &self.output
        }
    }
}
