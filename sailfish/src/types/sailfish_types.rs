use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedAuctionResult;

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedBlockHeader {
    pub metadata: UnusedMetadata,
}

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedMetadata;

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedBlockPayload;

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedTransaction;

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedInstanceState;

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedValidatedState;

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct UnusedDelta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusedError;

#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub struct UnusedVersions;
