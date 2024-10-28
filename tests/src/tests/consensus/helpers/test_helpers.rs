use hotshot_types::data::ViewNumber;
use sailfish::consensus::committee::StaticCommittee;
use sailfish::consensus::Consensus;
use sailfish::sailfish::generate_key_pair;
use sailfish::types::envelope::Envelope;
use sailfish::types::{
    message::{Action, Timeout},
    PublicKey,
};
use sailfish::types::{NodeId, PrivateKey};

const SEED: [u8; 32] = [0u8; 32];

pub(crate) fn make_consensus_nodes(num_nodes: u64) -> Vec<(PublicKey, Consensus)> {
    let keys = (0..num_nodes)
        .map(|i| generate_key_pair(SEED, i))
        .collect::<Vec<_>>();
    let committee = StaticCommittee::new(keys.iter().map(|(_, k)| k).cloned().collect());
    keys.into_iter()
        .enumerate()
        .map(|(i, (private_key, pub_key))| {
            let node_id = NodeId::from(i as u64);
            (
                pub_key,
                Consensus::new(node_id, pub_key, private_key, committee.clone()),
            )
        })
        .collect()
}

pub(crate) fn create_timeout_vote_action(
    timeout_round: ViewNumber,
    pub_key: PublicKey,
    private_key: &PrivateKey,
) -> Action {
    let data = Timeout::new(timeout_round);
    let e = Envelope::signed(data, private_key, pub_key);
    Action::SendTimeout(e)
}
