use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
};
use futures::future::join_all;
use timeboost_core::types::block::sailfish::SailfishBlock;

pub struct GasEstimator {
    nitro_url: &'static str,
}

/// Arbitrum gas estimator
impl GasEstimator {
    pub fn new(nitro_url: &'static str) -> Self {
        Self { nitro_url }
    }
    pub async fn estimate(&self, b: SailfishBlock) -> Result<(u64, SailfishBlock), EstimatorError> {
        // TODO: This will be pulled from transaction data in the block
        let from = "0xC0958d9EB0077bf6f7c1a5483AD332a81477d15E"
            .parse::<Address>()
            .map_err(|_| EstimatorError::FailedToParseWalletAddress)?;
        let to = "0x388A954C6b7282427AA2E8AF504504Fa6bA89432"
            .parse::<Address>()
            .map_err(|_| EstimatorError::FailedToParseWalletAddress)?;

        let p = ProviderBuilder::new().on_http(self.nitro_url.parse().expect("valid url"));

        let futs = b.transactions_ref().iter().map(|_tx| async {
            //TODO: Use the real transactions populate more fields
            let tx = TransactionRequest {
                from: Some(from),
                to: Some(to.into()),
                ..Default::default()
            };
            match p.estimate_gas(&tx).await {
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
