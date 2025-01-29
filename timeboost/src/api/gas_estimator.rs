use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use timeboost_core::types::{block::sailfish::SailfishBlock, transaction::Transaction};

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

pub struct GasEstimator {
    client: Client,
    arb_url: &'static str,
}

impl Default for GasEstimator {
    fn default() -> Self {
        Self {
            client: Client::new(),
            // TODO: Get a different URL this is getting rate limited
            // probably this https://docs.alchemy.com/reference/eth-estimategas
            arb_url: "https://arb1.arbitrum.io/rpc",
        }
    }
}

/// Arbitrum gas estimator https://docs.arbitrum.io/build-decentralized-apps/how-to-estimate-gas
impl GasEstimator {
    pub async fn estimate(
        &self,
        b: SailfishBlock,
    ) -> Result<(u64, SailfishBlock), (reqwest::Error, SailfishBlock)> {
        if b.is_empty() {
            return Ok((0, b));
        }
        match self.estimate_l2_gas_limit(b.transactions_ref()).await {
            Ok(estimate) => Ok((estimate, b)),
            Err(e) => Err((e, b)),
        }
    }

    // Estimate Gas Limit
    async fn estimate_l2_gas_limit(&self, txns: &[Transaction]) -> Result<u64, reqwest::Error> {
        // TODO: Real transactions + data
        let mut req = vec![];
        for (i, _tx) in txns.iter().enumerate() {
            let request = RpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "eth_estimateGas".to_string(),
                params: vec![
                    json!({
                        "from": "0xC0958d9EB0077bf6f7c1a5483AD332a81477d15E",
                        "to": "0x388A954C6b7282427AA2E8AF504504Fa6bA89432",
                    }),
                    json!("latest"),
                ],
                id: i as u32 + 1,
            };
            req.push(request);
        }

        let response = self.client.post(self.arb_url).json(&req).send().await?;
        let json: Result<Vec<RpcResponse>, reqwest::Error> = response.json().await;

        match json {
            Ok(responses) => {
                let mut estimated = 0;
                for r in responses {
                    estimated += u64::from_str_radix(r.result.trim_start_matches("0x"), 16)
                        .expect("valid response from api");
                }
                Ok(estimated)
            }
            Err(e) => {
                tracing::error!("error: {:?}", e);
                Err(e)
            }
        }
    }
}
