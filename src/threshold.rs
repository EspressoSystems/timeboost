use crate::{membership::Membership, signature_key::SignatureKey};
use serde::{Deserialize, Serialize};

/// Trait which allows use to inject different threshold calculations into a Certificate type
pub trait Threshold<KEY: SignatureKey> {
    /// Calculate a threshold based on the membership
    fn threshold<MEMBERSHIP: Membership<KEY>>(membership: &MEMBERSHIP) -> u64;
}

/// Defines a threshold which is 2f + 1 (Amount needed for Quorum)
#[derive(Serialize, Deserialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct SuccessThreshold {}

impl<KEY: SignatureKey> Threshold<KEY> for SuccessThreshold {
    fn threshold<MEMBERSHIP: Membership<KEY>>(membership: &MEMBERSHIP) -> u64 {
        membership.success_threshold().into()
    }
}

/// Defines a threshold which is f + 1 (i.e at least one of the stake is honest)
#[derive(Serialize, Deserialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct OneHonestThreshold {}

impl<KEY: SignatureKey> Threshold<KEY> for OneHonestThreshold {
    fn threshold<MEMBERSHIP: Membership<KEY>>(membership: &MEMBERSHIP) -> u64 {
        membership.failure_threshold().into()
    }
}
