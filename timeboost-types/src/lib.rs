mod block;
mod bundle;
mod bytes;
mod candidate_list;
mod decryption;
mod delayed_inbox;
mod inclusion_list;
mod retry_list;
mod seqno;
mod time;

pub mod math;

pub use block::{Block, BlockHash, BlockNumber};
pub use bundle::{
    Address, Bundle, BundleVariant, ChainId, PriorityBundle, SignedPriorityBundle, Signer,
    Transaction,
};
pub use bytes::Bytes;
pub use candidate_list::{CandidateList, CandidateListBytes};
pub use decryption::{DecShareKey, DecryptionKey, ShareInfo};
pub use delayed_inbox::DelayedInboxIndex;
pub use inclusion_list::InclusionList;
use multisig::{Envelope, Unchecked};
pub use retry_list::RetryList;
pub use seqno::SeqNo;
use serde::{Deserialize, Serialize};
pub use time::{Epoch, Timestamp};

#[derive(Serialize, Deserialize, Debug)]
pub enum MultiplexMessage {
    Decrypt(ShareInfo),
    Block(Envelope<BlockHash, Unchecked>),
}
