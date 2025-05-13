use sailfish_types::RoundNumber;
use serde::{Deserialize, Serialize};
use timeboost_crypto::{
    DecryptionScheme, KeysetId, Nonce, traits::threshold_enc::ThresholdEncScheme,
};

type KeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
type PublicKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;
type CombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;

/// Key materials related to the decryption phase, including the public key for encryption,
/// the per-node key share for decryption, and combiner key for hatching decryption shares into
/// plaintext
#[derive(Debug, Clone)]
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

/// TODO: (alex) remove this? this is decryption phase specific temp struct. not exposing externally
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

/// Metadata of a decryption share, including the round number it belongs to, a ciphertext identifier
/// (currently using the nonce inside the ciphertext since it's never reused), and the keyset id.
// TODO: (alex) see if we can simplify this to a mere cid?
#[derive(Clone, Debug, Hash, Serialize, Deserialize, Ord, PartialEq, Eq, PartialOrd)]
pub struct DecShareMetadata {
    round: RoundNumber,
    cid: Nonce,
    kid: KeysetId,
}

impl DecShareMetadata {
    pub fn new(round: RoundNumber, cid: Nonce, kid: KeysetId) -> Self {
        DecShareMetadata { round, cid, kid }
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
