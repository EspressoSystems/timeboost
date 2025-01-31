use std::fmt;

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::TransactionRequest,
    transports::http::Http,
};
use futures::future::join_all;
use reqwest::Client;
use timeboost_core::types::block::sailfish::SailfishBlock;

pub struct GasEstimator {
    provider: RootProvider<Http<Client>>,
}

/// Arbitrum gas estimator
impl GasEstimator {
    pub fn new(nitro_url: &str) -> Self {
        Self {
            provider: ProviderBuilder::new().on_http(nitro_url.parse().expect("valid url")),
        }
    }
    pub async fn estimate(&self, b: SailfishBlock) -> Result<(u64, SailfishBlock), EstimatorError> {
        // TODO: This will be pulled from transaction data in the block
        let from = "0xC0958d9EB0077bf6f7c1a5483AD332a81477d15E"
            .parse::<Address>()
            .map_err(|_| EstimatorError::FailedToParseWalletAddress)?;
        let to = "0x388A954C6b7282427AA2E8AF504504Fa6bA89432"
            .parse::<Address>()
            .map_err(|_| EstimatorError::FailedToParseWalletAddress)?;

        let futs = b.transactions_ref().iter().map(|_tx| async {
            //TODO: Use the real transactions populate more fields
            let tx = TransactionRequest {
                from: Some(from),
                to: Some(to.into()),
                ..Default::default()
            };
            match self.provider.estimate_gas(&tx).await {
                Ok(gas) => Some(gas),
                Err(e) => {
                    tracing::error!("failed to estimate gas for transaction: {:?}", e);
                    None
                }
            }
        });
        let estimates = join_all(futs)
            .await
            .iter()
            .try_fold(0u64, |acc, est| est.map(|v| acc + v));
        match estimates {
            Some(est) => Ok((est, b)),
            None => Err(EstimatorError::FailedToEstimateTxn(b)),
        }
    }
}

#[derive(Debug)]
pub enum EstimatorError {
    FailedToEstimateTxn(SailfishBlock),
    FailedToParseWalletAddress,
}

impl fmt::Display for EstimatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EstimatorError::FailedToEstimateTxn(block) => {
                write!(
                    f,
                    "failed to estimate gas for transaction, block len: {:?}",
                    block.len()
                )
            }
            EstimatorError::FailedToParseWalletAddress => {
                write!(f, "failed to parse wallet address")
            }
        }
    }
}
