use crate::{Address, Epoch};

#[derive(Clone, Debug)]
pub struct Auction {
    contract: Address,
}

impl Auction {
    pub fn new<C>(contract: C) -> Self
    where
        C: Into<Address>,
    {
        Self {
            contract: contract.into(),
        }
    }

    pub fn controller(&self, _: Epoch) -> Address {
        // TODO: return actual controller address
        Address::default()
    }

    pub fn contract(&self) -> Address {
        self.contract
    }

    pub async fn go(self) {
        // TODO: sync with auction contract
    }
}
