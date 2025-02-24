use sailfish_types::RoundNumber;
use serde::{Deserialize, Serialize};
use timeboost_crypto::{traits::threshold_enc::ThresholdEncScheme, DecryptionScheme};

type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;

/// Representing a set of shares from a single Timeboost node.
/// If a round has multiple encrypted items (ciphertexts),
/// they are "batched" in `ciphertexts` and `decryption_shares`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareInfo {
    pub round: RoundNumber,
    pub index: u64,
    pub ciphertexts: Vec<Ciphertext>,
    pub decryption_shares: Vec<DecShare>,
}
