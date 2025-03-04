use sailfish_types::RoundNumber;
use serde::{Deserialize, Serialize};
use timeboost_crypto::{
    traits::threshold_enc::ThresholdEncScheme, DecryptionScheme, KeysetId, Nonce,
};

type KeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
type PublicKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;
type CombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;

#[derive(Debug)]
pub struct DecryptionKey {
    pubkey: PublicKey,
    combkey: CombKey,
    privkey: KeyShare,
}

impl DecryptionKey {
    pub fn new(pubkey: PublicKey, combkey: CombKey, privkey: KeyShare) -> Self {
        DecryptionKey {
            pubkey,
            combkey,
            privkey,
        }
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    pub fn combkey(&self) -> &CombKey {
        &self.combkey
    }

    pub fn privkey(&self) -> &KeyShare {
        &self.privkey
    }
}

/// Representing a set of shares from a single Timeboost node.
/// If a round has multiple encrypted items (ciphertexts),
/// they are "batched" in `ciphertexts` and `decryption_shares`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareInfo {
    round: RoundNumber,
    kids: Vec<KeysetId>,
    cids: Vec<Nonce>,
    dec_shares: Vec<DecShare>,
}

impl ShareInfo {
    pub fn new(
        round: RoundNumber,
        kids: Vec<KeysetId>,
        cids: Vec<Nonce>,
        dec_shares: Vec<DecShare>,
    ) -> Self {
        ShareInfo {
            round,
            kids,
            cids,
            dec_shares,
        }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn kids(&self) -> &[KeysetId] {
        &self.kids
    }

    pub fn cids(&self) -> &[Nonce] {
        &self.cids
    }

    pub fn dec_shares(&self) -> &[DecShare] {
        &self.dec_shares
    }
}

#[derive(Clone, Debug, Hash, Serialize, Deserialize, Ord, PartialEq, Eq, PartialOrd)]
pub struct DecShareKey {
    round: RoundNumber,
    cid: Nonce,
    kid: KeysetId,
}

impl DecShareKey {
    pub fn new(round: RoundNumber, cid: Nonce, kid: KeysetId) -> Self {
        DecShareKey { round, cid, kid }
    }

    pub fn round(&self) -> RoundNumber {
        self.round
    }

    pub fn cid(&self) -> &Nonce {
        &self.cid
    }

    pub fn kid(&self) -> &KeysetId {
        &self.kid
    }
}
