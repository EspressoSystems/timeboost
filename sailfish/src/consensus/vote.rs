use anyhow::Result;
use bitvec::{bitvec, vec::BitVec};
use committable::{Commitment, Committable};
use ethereum_types::U256;
use hotshot::types::{BLSPrivKey, BLSPubKey, SignatureKey};
use hotshot_types::data::ViewNumber;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash, marker::PhantomData};
use tracing::{debug, error};

use crate::types::certificate::Certificate;

use super::committee::StaticCommittee;

pub trait HasRoundNumber {
    fn round_number(&self) -> ViewNumber;
}

pub trait Voteable: Committable + HasRoundNumber + Clone {}
pub trait Vote: HasRoundNumber + Clone {
    type Data: Voteable;

    fn data(&self) -> &Self::Data;
    fn commitment(&self) -> Commitment<Self::Data>;
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SailfishVote<VoteData: Voteable> {
    /// The data that this vote is voting on.
    pub data: VoteData,

    /// The signature of the vote.
    pub signature: <BLSPubKey as SignatureKey>::PureAssembledSignatureType,

    /// The commitment of the vote data.
    pub commitment: Commitment<VoteData>,

    /// The signing key of the vote.
    pub signing_key: BLSPubKey,
}

impl<VoteData: Voteable> HasRoundNumber for SailfishVote<VoteData> {
    fn round_number(&self) -> ViewNumber {
        self.data.round_number()
    }
}

impl<VoteData: Voteable> Vote for SailfishVote<VoteData> {
    type Data = VoteData;

    fn data(&self) -> &Self::Data {
        &self.data
    }

    fn commitment(&self) -> Commitment<Self::Data> {
        self.commitment
    }
}

impl<VoteData: Voteable> SailfishVote<VoteData> {
    pub fn new(
        data: VoteData,
        signature: <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
        signing_key: BLSPubKey,
    ) -> Self {
        let commitment = data.commit();
        Self {
            data,
            signature,
            commitment,
            signing_key,
        }
    }

    pub fn create_signed_vote(
        data: VoteData,
        public_key: BLSPubKey,
        private_key: &BLSPrivKey,
    ) -> Result<Self> {
        let commitment = data.commit();
        let signature = BLSPubKey::sign(private_key, commitment.as_ref())?;

        Ok(Self::new(data, signature, public_key))
    }

    pub fn is_valid(&self, quorum_membership: &StaticCommittee) -> bool {
        self.signing_key
            .validate(&self.signature, self.commitment.as_ref())
            && quorum_membership.committee().contains(&self.signing_key)
    }

    pub fn round_number(&self) -> ViewNumber {
        self.data.round_number()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct VoteAccumulator<V: Vote, Cert: Certificate<V::Data>> {
    pub round_number: ViewNumber,
    pub votes: BTreeMap<ViewNumber, BTreeMap<BLSPubKey, SailfishVote<V::Data>>>,
    pub signers: (
        BitVec,
        Vec<<BLSPubKey as SignatureKey>::PureAssembledSignatureType>,
    ),
    pd: PhantomData<Cert>,
}

impl<V: Vote, Cert: Certificate<V::Data>> VoteAccumulator<V, Cert> {
    pub async fn new(vote: &SailfishVote<V::Data>, quorum_membership: &StaticCommittee) -> Self {
        Self {
            round_number: vote.data.round_number(),
            votes: BTreeMap::new(),
            signers: (bitvec![0; quorum_membership.total_nodes()], Vec::new()),
            pd: PhantomData,
        }
    }

    pub async fn accumulate(
        &mut self,
        vote: &SailfishVote<V::Data>,
        quorum_membership: &StaticCommittee,
    ) -> Option<Cert> {
        let round_number = vote.data.round_number();

        let key = vote.signing_key;

        if !key.validate(&vote.signature, vote.commitment.as_ref()) {
            debug!("Invalid vote signature");
            return None;
        }

        // Have we already seen this vote?
        if self
            .votes
            .entry(round_number)
            .or_default()
            .contains_key(&vote.signing_key)
        {
            return None;
        }

        // Is this key in the stake table?
        if !quorum_membership.committee().contains(&key) {
            debug!("Vote signing key not in quorum membership");
            return None;
        }
        // Update the signers for the index associated with this signing key.
        let Some(index) = quorum_membership.committee().iter().position(|k| k == &key) else {
            // We shouldn't get here
            error!(
                "Somehow the signing key was found in the committee, but not able to be found by index"
            );
            return None;
        };

        self.signers.0.set(index, true);
        self.signers.1.push(vote.signature.clone());

        self.votes
            .entry(round_number)
            .or_default()
            .insert(vote.signing_key, vote.clone());

        // Check if we have enough votes to form a certificate
        if self.votes[&round_number].len() >= quorum_membership.success_threshold().get() as usize {
            let pp = <BLSPubKey as SignatureKey>::public_parameter(
                quorum_membership.stake_table(),
                U256::from(quorum_membership.success_threshold().get()),
            );

            let sig = <BLSPubKey as SignatureKey>::assemble(&pp, &self.signers.0, &self.signers.1);

            Some(Cert::create_signed_certificate(
                vote.commitment,
                vote.data.clone(),
                sig,
                round_number,
            ))
        } else {
            None
        }
    }
}
