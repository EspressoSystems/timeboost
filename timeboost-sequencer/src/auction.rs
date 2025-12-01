#![allow(unused)]
use alloy::primitives::Address;

use timeboost_types::Epoch;

#[derive(Debug)]
pub struct Auction {
    contract: Address,
}

impl Auction {
    pub fn new(contract: Address) -> Self {
        Self { contract }
    }

    pub fn express_lane_controller(&self, epoch: Epoch) -> Address {
        // TODO: return actual controller address
        Address::default()
    }

    pub async fn go(self) {
        // TODO: sync with auction contract on L1
    }
}
