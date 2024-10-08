use std::{collections::BTreeSet, fmt::Debug, hash::Hash, num::NonZeroU64};

use crate::{stake_table::StakeTableEntry, RoundNumber, SignatureKey};

/// A protocol for determining membership in and participating in a committee.
pub trait Membership<KEY: SignatureKey>:
    Clone + Debug + Eq + PartialEq + Send + Sync + Hash + 'static
{
    /// Create a committee
    fn new(committee_members: Vec<StakeTableEntry<KEY>>) -> Self;

    /// Get all participants in the committee (including their stake)
    fn stake_table(&self) -> Vec<<KEY as SignatureKey>::StakeTableEntry>;

    /// Get all participants in the committee for a specific view
    fn committee_members(&self, view_number: RoundNumber) -> BTreeSet<KEY>;

    /// Get all leaders in the committee for a specific view
    fn committee_leaders(&self, view_number: RoundNumber) -> BTreeSet<KEY>;

    /// Get the stake table entry for a public key, returns `None` if the
    /// key is not in the table
    fn stake(&self, pub_key: &KEY) -> Option<<KEY as SignatureKey>::StakeTableEntry>;

    /// See if a node has stake in the committee
    fn has_stake(&self, pub_key: &KEY) -> bool;

    /// The leader of the committee for view `view_number`.
    fn leader(&self, view_number: RoundNumber) -> KEY;

    /// Returns the number of total nodes in the committee
    fn total_nodes(&self) -> usize;

    /// Returns the threshold for a specific `Membership` implementation
    fn success_threshold(&self) -> NonZeroU64;

    /// Returns the threshold for a specific `Membership` implementation
    fn failure_threshold(&self) -> NonZeroU64;

    /// Returns the threshold required to upgrade the network protocol
    fn upgrade_threshold(&self) -> NonZeroU64;
}
