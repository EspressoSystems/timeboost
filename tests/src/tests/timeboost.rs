mod block_order;
mod handover;
mod test_timeboost_startup;
mod transaction_order;

use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

use alloy_eips::BlockNumberOrTag;
use cliquenet::{Address, AddressableCommittee};
use multisig::Keypair;
use multisig::{Committee, x25519};
use sailfish_types::UNKNOWN_COMMITTEE_ID;
use timeboost::types::BundleVariant;
use timeboost::types::DecryptionKey;
use timeboost_builder::CertifierConfig;
use timeboost_crypto::DecryptionScheme;
use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;
use timeboost_sequencer::SequencerConfig;
use timeboost_types::ChainConfig;
use timeboost_utils::load_generation::make_bundle;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;
use url::Url;

fn make_configs<R>(
    size: NonZeroUsize,
    recover_index: R,
) -> (
    <DecryptionScheme as ThresholdEncScheme>::PublicKey,
    Vec<(SequencerConfig, CertifierConfig)>,
)
where
    R: Into<Option<usize>>,
{
    let parts = (0..size.into())
        .map(|_| {
            let p1 = portpicker::pick_unused_port().unwrap();
            let p2 = portpicker::pick_unused_port().unwrap();
            let p3 = portpicker::pick_unused_port().unwrap();
            let a1 = Address::from((Ipv4Addr::LOCALHOST, p1));
            let a2 = Address::from((Ipv4Addr::LOCALHOST, p2));
            let a3 = Address::from((Ipv4Addr::LOCALHOST, p3));
            (
                Keypair::generate(),
                x25519::Keypair::generate().unwrap(),
                a1,
                a2,
                a3,
            )
        })
        .collect::<Vec<_>>();

    let committee = Committee::new(
        UNKNOWN_COMMITTEE_ID,
        parts
            .iter()
            .enumerate()
            .map(|(i, (kp, ..))| (i as u8, kp.public_key())),
    );
    let (pubkey, combkey, shares) = DecryptionScheme::trusted_keygen(committee.clone());

    let sailfish_committee = AddressableCommittee::new(
        committee.clone(),
        parts
            .iter()
            .map(|(kp, xp, sa, ..)| (kp.public_key(), xp.public_key(), sa.clone())),
    );

    let decrypt_committee = AddressableCommittee::new(
        committee.clone(),
        parts
            .iter()
            .map(|(kp, xp, _, da, ..)| (kp.public_key(), xp.public_key(), da.clone())),
    );

    let produce_committee = AddressableCommittee::new(
        committee.clone(),
        parts
            .iter()
            .map(|(kp, xp, _, _, pa, ..)| (kp.public_key(), xp.public_key(), pa.clone())),
    );

    let mut cfgs = Vec::new();
    let recover_index = recover_index.into();

    for (i, ((kpair, xpair, sa, da, pa), share)) in parts.into_iter().zip(shares).enumerate() {
        let dkey = DecryptionKey::new(pubkey.clone(), combkey.clone(), share.clone());
        let conf = SequencerConfig::builder()
            .sign_keypair(kpair.clone())
            .dh_keypair(xpair.clone())
            .decryption_key(dkey)
            .sailfish_addr(sa)
            .decrypt_addr(da)
            .sailfish_committee(sailfish_committee.clone())
            .decrypt_committee(decrypt_committee.clone())
            .recover(recover_index.map(|r| r == i).unwrap_or(false))
            .leash_len(100)
            .chain_config(ChainConfig::new(
                1,
                "https://theserversroom.com/ethereum/54cmzzhcj1o/"
                    .parse::<Url>()
                    .expect("valid url"),
                "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f"
                    .parse::<alloy_primitives::Address>()
                    .expect("valid contract"),
                BlockNumberOrTag::Finalized,
            ))
            .build();
        let pcf = CertifierConfig::builder()
            .sign_keypair(kpair)
            .dh_keypair(xpair)
            .address(pa)
            .committee(produce_committee.clone())
            .build();
        cfgs.push((conf, pcf));
    }

    (pubkey, cfgs)
}

/// Generate random bundles at a fixed frequency.
async fn gen_bundles(
    pubkey: <DecryptionScheme as ThresholdEncScheme>::PublicKey,
    tx: broadcast::Sender<BundleVariant>,
) {
    loop {
        let Ok(b) = make_bundle(&pubkey) else {
            warn!("Failed to generate bundle");
            continue;
        };
        if tx.send(b).is_err() {
            warn!("Failed to broadcast bundle");
            return;
        }
        sleep(Duration::from_millis(10)).await
    }
}
