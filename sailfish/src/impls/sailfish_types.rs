use std::error::Error;

use committable::Committable;
use hotshot::{
    traits::{election::static_committee::StaticCommittee, BlockPayload, ValidatedState},
    types::BLSPubKey,
};
use hotshot_types::{
    data::ViewNumber,
    traits::{
        block_contents::{
            BlockHeader as HotShotBlockHeader, EncodeBytes, Transaction as HotShotTransaction,
        },
        node_implementation::{HasUrls, NodeType},
        states::{InstanceState, StateDelta},
    },
    utils::BuilderCommitment,
};
use serde::{Deserialize, Serialize};
use url::Url;
use vbs::version::Version;

use crate::types::sailfish_types::{
    UnusedAuctionResult, UnusedBlockHeader, UnusedBlockPayload, UnusedDelta, UnusedError,
    UnusedInstanceState, UnusedMetadata, UnusedTransaction, UnusedValidatedState,
};
// TODO: This sucks.
impl HasUrls for UnusedAuctionResult {
    fn urls(&self) -> Vec<Url> {
        vec![]
    }
}
impl Committable for UnusedBlockHeader {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("UnusedBlockHeader").finalize()
    }
}

impl HotShotBlockHeader<SailfishTypes> for UnusedBlockHeader {
    type Error = UnusedError;

    async fn new_legacy(
        _parent_state: &<SailfishTypes as NodeType>::ValidatedState,
        _instance_state: &<<SailfishTypes as NodeType>::ValidatedState as hotshot::traits::ValidatedState<SailfishTypes>>::Instance,
        _parent_leaf: &hotshot_types::data::Leaf<SailfishTypes>,
        _payload_commitment: hotshot_types::vid::VidCommitment,
        _builder_commitment: hotshot_types::utils::BuilderCommitment,
        _metadata: <<SailfishTypes as NodeType>::BlockPayload as hotshot::traits::BlockPayload<
            SailfishTypes,
        >>::Metadata,
        _builder_fee: hotshot_types::traits::block_contents::BuilderFee<SailfishTypes>,
        _vid_common: hotshot_types::vid::VidCommon,
        _version: Version,
    ) -> Result<Self, Self::Error> {
        Ok(UnusedBlockHeader {
            metadata: UnusedMetadata,
        })
    }

    async fn new_marketplace(
        _parent_state: &<SailfishTypes as NodeType>::ValidatedState,
        _instance_state: &<<SailfishTypes as NodeType>::ValidatedState as hotshot::traits::ValidatedState<SailfishTypes>>::Instance,
        _parent_leaf: &hotshot_types::data::Leaf<SailfishTypes>,
        _payload_commitment: hotshot_types::vid::VidCommitment,
        _builder_commitment: hotshot_types::utils::BuilderCommitment,
        _metadata: <<SailfishTypes as NodeType>::BlockPayload as hotshot::traits::BlockPayload<
            SailfishTypes,
        >>::Metadata,
        _builder_fee: Vec<hotshot_types::traits::block_contents::BuilderFee<SailfishTypes>>,
        _vid_common: hotshot_types::vid::VidCommon,
        _auction_results: Option<<SailfishTypes as NodeType>::AuctionResult>,
        _version: Version,
    ) -> Result<Self, Self::Error> {
        Ok(UnusedBlockHeader {
            metadata: UnusedMetadata,
        })
    }

    fn genesis(
        _instance_state: &<<SailfishTypes as NodeType>::ValidatedState as hotshot::traits::ValidatedState<SailfishTypes>>::Instance,
        _payload_commitment: hotshot_types::vid::VidCommitment,
        _builder_commitment: hotshot_types::utils::BuilderCommitment,
        _metadata: <<SailfishTypes as NodeType>::BlockPayload as hotshot::traits::BlockPayload<
            SailfishTypes,
        >>::Metadata,
    ) -> Self {
        UnusedBlockHeader {
            metadata: UnusedMetadata,
        }
    }

    fn block_number(&self) -> u64 {
        0
    }

    fn payload_commitment(&self) -> hotshot_types::vid::VidCommitment {
        hotshot_types::vid::VidCommitment::default()
    }
    fn metadata(
        &self,
    ) -> &<<SailfishTypes as NodeType>::BlockPayload as BlockPayload<SailfishTypes>>::Metadata {
        &self.metadata
    }

    fn builder_commitment(&self) -> BuilderCommitment {
        BuilderCommitment::from_bytes(vec![])
    }

    fn get_auction_results(&self) -> Option<<SailfishTypes as NodeType>::AuctionResult> {
        None
    }
}

impl EncodeBytes for UnusedMetadata {
    fn encode(&self) -> std::sync::Arc<[u8]> {
        vec![].into()
    }
}

impl InstanceState for UnusedInstanceState {}
impl HotShotTransaction for UnusedTransaction {}
impl Committable for UnusedTransaction {
    fn commit(&self) -> committable::Commitment<Self> {
        committable::RawCommitmentBuilder::new("UnusedTransaction").finalize()
    }
}
impl StateDelta for UnusedDelta {}
impl ValidatedState<SailfishTypes> for UnusedValidatedState {
    type Error = UnusedError;

    type Instance = UnusedInstanceState;

    type Delta = UnusedDelta;

    type Time = ViewNumber;

    async fn validate_and_apply_header(
        &self,
        _instance: &Self::Instance,
        _parent_leaf: &hotshot_types::data::Leaf<SailfishTypes>,
        _proposed_header: &<SailfishTypes as NodeType>::BlockHeader,
        _vid_common: hotshot_types::vid::VidCommon,
        _version: Version,
    ) -> Result<(Self, Self::Delta), Self::Error> {
        Ok((UnusedValidatedState, UnusedDelta))
    }

    fn from_header(_block_header: &<SailfishTypes as NodeType>::BlockHeader) -> Self {
        UnusedValidatedState
    }

    fn genesis(_instance: &Self::Instance) -> (Self, Self::Delta) {
        (UnusedValidatedState, UnusedDelta)
    }

    fn on_commit(&self) {}
}

impl std::fmt::Display for UnusedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnusedError DO NOT USE THIS. IF YOU SEE THIS SOMETHING IS WRONG."
        )
    }
}

impl Error for UnusedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}

impl EncodeBytes for UnusedBlockPayload {
    fn encode(&self) -> std::sync::Arc<[u8]> {
        vec![].into()
    }
}

impl std::fmt::Display for UnusedBlockPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnusedBlockPayload DO NOT USE THIS. IF YOU SEE THIS SOMETHING IS WRONG."
        )
    }
}

#[async_trait::async_trait]
impl BlockPayload<SailfishTypes> for UnusedBlockPayload {
    /// The error type for this type of block
    type Error = UnusedError;

    /// The type of the instance-level state this state is associated with
    type Instance = UnusedInstanceState;

    /// The type of the transitions we are applying
    type Transaction = UnusedTransaction;

    /// Validated State
    type ValidatedState = UnusedValidatedState;

    /// Data created during block building which feeds into the block header
    type Metadata = UnusedMetadata;

    /// Build a payload and associated metadata with the transactions.
    /// This function is asynchronous because it may need to request updated state from the peers via GET requests.
    /// # Errors
    /// If the transaction length conversion fails.
    async fn from_transactions(
        _transactions: impl IntoIterator<Item = Self::Transaction> + Send,
        _validated_state: &Self::ValidatedState,
        _instance_state: &Self::Instance,
    ) -> Result<(Self, Self::Metadata), Self::Error> {
        Ok((UnusedBlockPayload, UnusedMetadata))
    }

    /// Build a payload with the encoded transaction bytes, metadata,
    /// and the associated number of VID storage nodes
    fn from_bytes(_encoded_transactions: &[u8], _metadata: &Self::Metadata) -> Self {
        UnusedBlockPayload
    }

    /// Build the payload and metadata for genesis/null block.
    fn empty() -> (Self, Self::Metadata) {
        (UnusedBlockPayload, UnusedMetadata)
    }

    /// Generate commitment that builders use to sign block options.
    fn builder_commitment(&self, _metadata: &Self::Metadata) -> BuilderCommitment {
        BuilderCommitment::from_bytes(vec![])
    }

    /// Get the transactions in the payload.
    fn transactions<'a>(
        &'a self,
        _metadata: &'a Self::Metadata,
    ) -> impl 'a + Iterator<Item = Self::Transaction> {
        vec![].into_iter()
    }
}

#[derive(
    Clone, Debug, Default, Serialize, Deserialize, Copy, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct SailfishTypes;

impl NodeType for SailfishTypes {
    type Time = ViewNumber;

    type AuctionResult = UnusedAuctionResult;

    type BlockHeader = UnusedBlockHeader;

    type BlockPayload = UnusedBlockPayload;

    type SignatureKey = BLSPubKey;

    type Transaction = UnusedTransaction;

    type InstanceState = UnusedInstanceState;

    type ValidatedState = UnusedValidatedState;

    type Membership = StaticCommittee<Self>;

    type BuilderSignatureKey = BLSPubKey;
}
