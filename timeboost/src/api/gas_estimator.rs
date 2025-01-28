use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use timeboost_core::types::block::sailfish::SailfishBlock;
use tokio::try_join;

#[derive(Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u32,
}

#[derive(Deserialize, Serialize)]
struct RpcResponse {
    jsonrpc: String,
    result: String,
    id: u64,
}

pub(crate) struct GasEstimator {
    client: Client,
    arb_url: &'static str,
}

/// Gas estimator based on https://docs.arbitrum.io/build-decentralized-apps/how-to-estimate-gas
impl GasEstimator {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            // TODO: Get a different URL this is getting rate limited
            // probably this https://docs.alchemy.com/reference/eth-estimategas
            arb_url: "https://arb1.arbitrum.io/rpc",
        }
    }

    pub async fn estimate(&self, txns: &[SailfishBlock]) -> Result<u64, reqwest::Error> {
        if txns.is_empty() {
            return Ok(0);
        }
        let (price, estimate) = try_join!(
            self.get_l2_gas_price(),
            self.estimate_l2_gas_limit("0xd3CdA913deB6f67967B99D67aCDFa1712C293601", txns, 0x0)
        )?;

        let tx_fees = price * estimate;
        tracing::info!("txn_fees: {}", tx_fees);

        Ok(tx_fees)
    }

    // Fetch L2 Gas Price
    async fn get_l2_gas_price(&self) -> Result<u64, reqwest::Error> {
        let request_body = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "eth_gasPrice".to_string(),
            params: vec![],
            id: 1,
        };

        let response = self
            .client
            .post(self.arb_url)
            .json(&request_body)
            .send()
            .await?;

        let gas: RpcResponse = response.json().await?;

        // Convert from hex (Gwei) to u64
        let gas_price = u64::from_str_radix(gas.result.trim_start_matches("0x"), 16).unwrap();
        Ok(gas_price)
    }

    // Estimate Gas Limit
    async fn estimate_l2_gas_limit(
        &self,
        to: &str,
        _txn: &[SailfishBlock],
        _value: u64,
    ) -> Result<u64, reqwest::Error> {
        // TODO: Batch the request with proper transactions
        let request_body = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "eth_estimateGas".to_string(),
            params: vec![
                json!({
                    "to": to,
                    "value": "0x0",
                }),
                json!("latest"),
            ],
            id: 1,
        };

        let response = self
            .client
            .post(self.arb_url)
            .json(&request_body)
            .send()
            .await?;

        let r: RpcResponse = response.json().await?;

        // Convert from hex to u64
        let gas_limit = u64::from_str_radix(r.result.trim_start_matches("0x"), 16).unwrap();
        Ok(gas_limit)
    }
}
