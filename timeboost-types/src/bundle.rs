use core::fmt;
use std::ops::{Deref, DerefMut};

use alloy::consensus::TxEnvelope;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::{Error, SignerSync, k256::ecdsa::SigningKey};
use alloy_rlp::Decodable;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{CommitteeId, KeyId, PublicKey};
use serde::{Deserialize, Serialize};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Result, Unstructured};
use timeboost_crypto::prelude::{VessCiphertext, VssCommitment};

use crate::{Auction, Bytes, Epoch, SeqNo};

const DOMAIN: &str = "TIMEBOOST_BID";

#[derive(Debug, Clone)]
pub enum BundleVariant {
    Regular(Bundle),
    Priority(SignedPriorityBundle),
    Dkg(DkgBundle),
}

/// A bundle contains a list of transactions (encrypted or unencrypted, both encoded as `Bytes`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Bundle {
    chain_id: ChainId,
    epoch: Epoch,
    data: Bytes,
    encrypted: bool,
    hash: [u8; 32],
}

impl Bundle {
    pub fn new(chain_id: ChainId, epoch: Epoch, data: Bytes, encrypted: bool) -> Self {
        let mut this = Self {
            chain_id,
            epoch,
            data,
            encrypted,
            hash: [0; 32],
        };
        this.update_hash();
        this
    }

    fn update_hash(&mut self) {
        let digest = self.commit();
        self.hash = digest.into();
    }
}

impl Bundle {
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Set the data payload to some ciphertext bytes
    pub fn set_encrypted_data(&mut self, d: Bytes) {
        self.data = d;
        self.encrypted = true;
        self.update_hash()
    }

    /// Set the data payload to un-encrypted, plaintext data.
    /// Use this at the end of the decryption phase
    pub fn set_data(&mut self, d: Bytes) {
        self.data = d;
        self.encrypted = false;
        self.update_hash();
    }

    pub fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
        self.update_hash()
    }

    #[cfg(feature = "arbitrary")]
    pub fn arbitrary(u: &mut Unstructured<'_>) -> Result<Self, InvalidTransaction> {
        use alloy::rlp::Encodable;

        let t = loop {
            let candidate = TxEnvelope::arbitrary(u)?;
            if let TxEnvelope::Eip4844(ref eip4844) = candidate {
                if eip4844.tx().clone().try_into_4844_with_sidecar().is_ok() {
                    // Avoid generating 4844 Tx with blobs of size 131 KB
                    continue;
                }
            }
            break candidate;
        };

        let mut d = Vec::new();
        t.encode(&mut d);
        let c = ChainId::default();
        let e = Epoch::now() + bool::arbitrary(u)? as u64;
        let encoded = ssz::ssz_encode(&vec![&d]);
        let b = Bundle::new(c, e, encoded.into(), false);

        Ok(b)
    }
}

impl Committable for Bundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Bundle")
            .field("chain", self.chain_id().commit())
            .field("epoch", self.epoch().commit())
            .u64(if self.is_encrypted() { 1 } else { 0 })
            .var_size_field("data", self.data())
            .finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PriorityBundle {
    bundle: Bundle,
    auction: Address,
    seqno: SeqNo,
    hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct SignedPriorityBundle {
    priority: PriorityBundle,
    signature: Signature,
}

impl PriorityBundle {
    pub fn new(bundle: Bundle, auction: Address, seqno: SeqNo) -> Self {
        Self {
            auction,
            seqno,
            hash: [0; 32],
            bundle,
        }
    }

    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    pub fn auction(&self) -> Address {
        self.auction
    }

    pub fn seqno(&self) -> SeqNo {
        self.seqno
    }

    // https://github.com/OffchainLabs/nitro/blob/1e16dc408d24a7784f19acd1e76a71daac528a22/timeboost/types.go#L206
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN.as_bytes());
        buf.extend_from_slice(&self.bundle().chain_id.0.to_be_bytes());
        buf.extend_from_slice(self.auction.0.0.as_slice());
        buf.extend_from_slice(&self.bundle().epoch.to_be_bytes());
        buf.extend_from_slice(&self.seqno.to_be_bytes());
        buf.extend_from_slice(&self.bundle().data);
        buf
    }

    pub fn sign(self, signer: Signer) -> Result<SignedPriorityBundle, Error> {
        use alloy::signers::Signer;
        let signer = signer.0.with_chain_id(Some(self.bundle().chain_id().0));
        signer.sign_message_sync(&self.to_bytes()).map(|signature| {
            SignedPriorityBundle::new(
                self.bundle.clone(),
                self.auction,
                self.seqno,
                Signature(signature),
            )
        })
    }
}

impl Deref for SignedPriorityBundle {
    type Target = PriorityBundle;
    fn deref(&self) -> &Self::Target {
        &self.priority
    }
}

impl DerefMut for SignedPriorityBundle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.priority
    }
}

impl SignedPriorityBundle {
    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    // https://github.com/OffchainLabs/nitro/blob/1e16dc408d24a7784f19acd1e76a71daac528a22/execution/gethexec/express_lane_service.go#L309
    pub fn validate(&self, epoch: Epoch, auction: &Auction) -> Result<(), ValidationError> {
        if self.auction != auction.contract() {
            return Err(ValidationError::WrongAuctionContract(self.auction));
        }

        if !(self.bundle().epoch == epoch || self.bundle().epoch == epoch + 1) {
            return Err(ValidationError::BadRoundNumber(self.bundle().epoch));
        }

        if self.sender()? != auction.controller(self.bundle().epoch()) {
            return Err(ValidationError::NotPLC);
        }
        Ok(())
    }

    /// Attempts to extract the sender's address from the signature.
    /// Returns an error if the signature parsing fails.
    pub fn sender(&self) -> Result<Address, ValidationError> {
        let msg = self.to_bytes();
        let recovered = self.signature().recover_address_from_msg(msg);
        Ok(Address(
            recovered.map_err(|_| ValidationError::UnableToRecoverAddress)?,
        ))
    }

    /// Set the data payload to un-encrypted, plaintext data.
    pub fn set_data(&mut self, d: Bytes) {
        self.bundle.data = d;
        self.bundle.encrypted = false;
        self.update_hash()
    }

    fn new(bundle: Bundle, auction: Address, seqno: SeqNo, signature: Signature) -> Self {
        let mut this = Self {
            priority: PriorityBundle::new(bundle, auction, seqno),
            signature,
        };
        this.update_hash();
        this
    }

    fn update_hash(&mut self) {
        let digest = self.commit();
        self.hash = digest.into();
    }

    #[cfg(feature = "arbitrary")]
    pub fn arbitrary(
        u: &mut arbitrary::Unstructured<'_>,
        max_seqno: u64,
    ) -> Result<SignedPriorityBundle, InvalidTransaction> {
        let bundle = Bundle::arbitrary(u)?;
        let auction = Address::default();
        let seqno = SeqNo::from(u.int_in_range(1..=max_seqno)?);
        let priority_bundle = PriorityBundle::new(bundle, auction, seqno);

        let signer = Signer::default();
        let signed_bundle = priority_bundle.sign(signer).expect("default signer");
        Ok(signed_bundle)
    }
}

impl Committable for SignedPriorityBundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("SignedPriorityBundle")
            .field("bundle", self.bundle.commit())
            .field("auction", self.auction.commit())
            .field("seqno", self.seqno.commit())
            .field("signature", self.signature().commit())
            .finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgBundle {
    /// origin of the dkg bundle
    origin: (KeyId, PublicKey),
    /// target committee for the dkg bundle
    committee_id: CommitteeId,
    /// encrypted secret shares in a dealing
    vess_ct: VessCiphertext,
    /// Feldman commitment to the secret sharing dealing
    comm: VssCommitment,
}

impl DkgBundle {
    pub fn new(
        origin: (KeyId, PublicKey),
        committee_id: CommitteeId,
        vess_ct: VessCiphertext,
        comm: VssCommitment,
    ) -> Self {
        Self {
            origin,
            committee_id,
            vess_ct,
            comm,
        }
    }

    pub fn origin(&self) -> &(KeyId, PublicKey) {
        &self.origin
    }

    pub fn committee_id(&self) -> &CommitteeId {
        &self.committee_id
    }

    pub fn vess_ct(&self) -> &VessCiphertext {
        &self.vess_ct
    }

    pub fn comm(&self) -> &VssCommitment {
        &self.comm
    }
}

impl std::hash::Hash for DkgBundle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.commit().hash(state);
    }
}

impl Committable for DkgBundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("DkgBundle")
            .field("committee", self.committee_id.commit())
            .var_size_field("ciphertexts", self.vess_ct.as_bytes())
            .var_size_field(
                "commitment",
                &bincode::serde::encode_to_vec(&self.comm, bincode::config::standard())
                    .expect("bincode encdoe comm should succeed"),
            )
            .finalize()
    }
}

#[derive(
    Debug, Default, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChainId(alloy::primitives::ChainId);

impl From<u64> for ChainId {
    fn from(value: u64) -> Self {
        ChainId(value)
    }
}

impl From<ChainId> for u64 {
    fn from(value: ChainId) -> Self {
        value.0
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChainId({})", self.0)
    }
}

impl Committable for ChainId {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("ChainId").u64(self.0).finalize()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Transaction {
    tx: TxEnvelope,
}

impl std::ops::Deref for Transaction {
    type Target = TxEnvelope;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl Transaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidTransaction> {
        let mut buf = bytes;
        let tx = TxEnvelope::decode(&mut buf)?;
        Ok(Self { tx })
    }
}

// Address wrapper
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Address(alloy::primitives::Address);

impl std::ops::Deref for Address {
    type Target = alloy::primitives::Address;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for Address {
    fn default() -> Self {
        Signer::default().0.address().into()
    }
}

impl From<alloy::primitives::Address> for Address {
    fn from(address: alloy::primitives::Address) -> Self {
        Address(address)
    }
}

impl From<Address> for alloy::primitives::Address {
    fn from(eth_address: Address) -> Self {
        eth_address.0
    }
}

impl Committable for Address {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Address")
            .fixed_size_bytes(&self.0.0)
            .finalize()
    }
}

// Signature wrapper
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signature(alloy::signers::Signature);

impl std::ops::Deref for Signature {
    type Target = alloy::signers::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(&other.0.as_bytes())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Committable for Signature {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Signature")
            .fixed_size_bytes(&<[u8; 65]>::from(&self.0))
            .finalize()
    }
}

// Signer wrapper
pub struct Signer(alloy::signers::local::PrivateKeySigner);

impl Signer {
    pub fn address(&self) -> alloy::primitives::Address {
        self.0.address()
    }
}

impl Default for Signer {
    fn default() -> Self {
        let private_key_bytes = [0x01; 32];
        let signing_key =
            SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
        let private_key_signer = PrivateKeySigner::from_signing_key(signing_key);

        Signer(private_key_signer)
    }
}

impl From<alloy::signers::local::PrivateKeySigner> for Signer {
    fn from(signer: alloy::signers::local::PrivateKeySigner) -> Self {
        Signer(signer)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidTransaction {
    #[error("invalid signature: {0}")]
    Signature(#[from] alloy::primitives::SignatureError),

    #[error("recovery error: {0}")]
    Recovery(#[from] alloy::consensus::crypto::RecoveryError),

    #[error("invalid rlp encoding: {0}")]
    Rlp(#[from] alloy::rlp::Error),

    #[cfg(feature = "arbitrary")]
    #[error("arbitrary error: {0}")]
    Arbitrary(#[from] arbitrary::Error),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("bundle auction address {:?} does not match current auction address", .0)]
    WrongAuctionContract(Address),

    #[error("bundle round {:?} does not match current round", .0)]
    BadRoundNumber(Epoch),

    #[error("no controller available on-chain")]
    NoOnchainPLC,

    #[error("sender is not PLC for current round")]
    NotPLC,

    #[error("unable to recover signer address from signature")]
    UnableToRecoverAddress,
}

#[cfg(test)]
mod tests {
    use ark_std::rand;
    use ssz::ssz_encode;

    use crate::{Auction, Epoch, SeqNo, bundle::Address};

    use super::{Bundle, ChainId, PriorityBundle, SignedPriorityBundle, Signer};

    #[test]
    fn test_verify() -> Result<(), Box<dyn std::error::Error>> {
        let epoch = Epoch::from(0);
        let auction_contract = Address::default();
        let auction = Auction::new(auction_contract);
        let express_lane_address = auction.controller(epoch);
        let bundle = sample_bundle(express_lane_address).unwrap();
        let result = bundle.validate(epoch, &auction);
        assert_eq!(result, Ok(()));
        Ok(())
    }

    fn sample_bundle(express_lane_address: Address) -> anyhow::Result<SignedPriorityBundle> {
        let mut rlp_encoded_txns = Vec::new();
        for _ in 0..5 {
            let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            rlp_encoded_txns.push(random_bytes);
        }
        let ssz_encoded_txns = ssz_encode(&rlp_encoded_txns);
        let bundle = Bundle::new(
            ChainId::default(),
            Epoch::from(0),
            ssz_encoded_txns.into(),
            false,
        );
        let unsigned_priority = PriorityBundle::new(bundle, express_lane_address, SeqNo::zero());

        let signed_priority = unsigned_priority.sign(Signer::default());
        signed_priority.map_err(anyhow::Error::from)
    }
}
