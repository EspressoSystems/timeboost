use std::fmt;

use alloy::{
    network::Ethereum,
    providers::fillers::{FillProvider, TxFiller},
};
use alloy::{primitives::Address, providers::Provider, rpc::types::TransactionRequest};
use committable::{Commitment, Committable};
use futures::future::join_all;
use timeboost_core::types::block::sailfish::SailfishBlock;
use tracing::warn;

pub struct GasEstimator<F: TxFiller<Ethereum>, P: Provider<Ethereum>> {
    provider: FillProvider<F, P, Ethereum>,
}

/// Arbitrum gas estimator
impl<F, P> GasEstimator<F, P>
where
    F: TxFiller<Ethereum>,
    P: Provider<Ethereum>,
{
    pub fn new(p: FillProvider<F, P, Ethereum>) -> Self {
        Self { provider: p }
    }
    pub async fn estimate(
        &self,
        b: &SailfishBlock,
    ) -> Result<(Commitment<SailfishBlock>, u64), EstimatorError> {
        // TODO: This will be pulled from transaction data in the block
        let from = "0x593C4e4F4a0dCCf84A9C4f819BED466780c1d516"
            .parse::<Address>()
            .map_err(|_| EstimatorError::FailedToParseWalletAddress)?;
        let to = "0x0d5B8b79577aC3Bc5Fe47Cf82F5d0146BDCeBd9f"
            .parse::<Address>()
            .map_err(|_| EstimatorError::FailedToParseWalletAddress)?;
        let futs = b.transactions().iter().map(|_tx| async {
            // TODO: Use the real transactions and populate more fields such as data
            let tx = TransactionRequest {
                from: Some(from),
                to: Some(to.into()),
                ..Default::default()
            };
            match self.provider.estimate_gas(&tx).await {
                Ok(gas) => Some(gas),
                Err(e) => {
                    warn!("failed to estimate gas for transaction: {:?}", e);
                    None
                }
            }
        });
        let estimates = join_all(futs)
            .await
            .iter()
            .try_fold(0u64, |acc, est| est.map(|v| acc + v));
        match estimates {
            Some(est) => Ok((b.commit(), est)),
            None => Err(EstimatorError::FailedToEstimateTxn),
        }
    }
}

#[derive(Debug)]
pub enum EstimatorError {
    FailedToEstimateTxn,
    FailedToParseWalletAddress,
}

impl fmt::Display for EstimatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EstimatorError::FailedToEstimateTxn => {
                write!(f, "failed to estimate gas for transaction")
            }
            EstimatorError::FailedToParseWalletAddress => {
                write!(f, "failed to parse wallet address")
            }
        }
    }
}
