use timeboost_types::Address;

use crate::inclusion_list::ProtoAddress;

pub mod inclusion_list {
    include!("inclusion_list.rs");
}

impl From<Address> for ProtoAddress {
    fn from(addr: Address) -> Self {
        ProtoAddress {
            hex: addr.to_string(),
            raw: addr.as_slice().to_vec(),
        }
    }
}
