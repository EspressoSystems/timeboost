use std::fmt;

use alloy::{
    network::Ethereum,
    primitives::TxKind,
    providers::{
        fillers::{FillProvider, TxFiller},
        Provider,
    },
};
use alloy::{primitives::Address, rpc::types::TransactionRequest};
use committable::{Commitment, Committable};
use futures::future::join_all;
use timeboost_core::types::{block::sailfish::SailfishBlock, transaction::Transaction};
use tracing::{info, warn};

pub struct NitroProvider<F: TxFiller<Ethereum>, P: Provider<Ethereum>> {
    provider: FillProvider<F, P, Ethereum>,
}

/// Alloy nitro provider
impl<F, P> NitroProvider<F, P>
where
    F: TxFiller<Ethereum>,
    P: Provider<Ethereum>,
{
    pub fn new(p: FillProvider<F, P, Ethereum>) -> Self {
        Self { provider: p }
    }

    /// Estimates the gas required for all transactions within a given block.
    ///
    /// This function:
    /// - Iterates over each transaction in the provided `SailfishBlock`.
    /// - Generates a gas estimate for each transaction using a placeholder `TransactionRequest`.
    /// - Aggregates these estimates to return a total gas estimation for the block.
    pub async fn estimate(
        &self,
        b: &SailfishBlock,
    ) -> Result<(Commitment<SailfishBlock>, u64), ProviderError> {
        // TODO: This will be pulled from transaction data in the block
        let from = "0x593C4e4F4a0dCCf84A9C4f819BED466780c1d516"
            .parse::<Address>()
            .map_err(|_| ProviderError::FailedToParseWalletAddress)?;
        let to = "0x0d5B8b79577aC3Bc5Fe47Cf82F5d0146BDCeBd9f"
            .parse::<Address>()
            .map_err(|_| ProviderError::FailedToParseWalletAddress)?;
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
            None => Err(ProviderError::FailedToEstimateTxn),
        }
    }

    /// Send the transactions to nitro
    pub async fn send_txns(&self, txns: &[Transaction]) -> Result<(), ProviderError> {
        // TODO: Pull from transaction vec
        let from = "0x593C4e4F4a0dCCf84A9C4f819BED466780c1d516"
            .parse::<Address>()
            .map_err(|_| ProviderError::FailedToParseWalletAddress)?;
        let to = "0x0d5B8b79577aC3Bc5Fe47Cf82F5d0146BDCeBd9f"
            .parse::<Address>()
            .map_err(|_| ProviderError::FailedToParseWalletAddress)?;
        let futs = txns.iter().map(|tx| async move {
            // TODO: Proper fields
            let t = match tx {
                Transaction::Priority {
                    nonce: _,
                    to: _,
                    txns: _,
                } => TransactionRequest {
                    from: Some(from),
                    to: Some(TxKind::Call(to)),
                    ..Default::default()
                },
                Transaction::Regular { txn: _ } => TransactionRequest {
                    from: Some(from),
                    to: Some(TxKind::Call(to)),
                    ..Default::default()
                },
            };
            match self.provider.send_transaction(t).await {
                Ok(_) => {
                    info!("sent tx")
                }
                Err(e) => {
                    warn!("failed to send tx: {:?}", e)
                }
            }
        });
        let _ = join_all(futs).await;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ProviderError {
    FailedToEstimateTxn,
    FailedToParseWalletAddress,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderError::FailedToEstimateTxn => {
                write!(f, "failed to estimate gas for transaction")
            }
            ProviderError::FailedToParseWalletAddress => {
                write!(f, "failed to parse wallet address")
            }
        }
    }
}
