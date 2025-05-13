use std::ops::{Deref, DerefMut};

use alloy_consensus::{Sealed, TxEnvelope};

use alloy_eips::{Encodable2718, Typed2718};
use alloy_primitives::B256;
use alloy_rlp::Decodable;
use alloy_signer::{Error, SignerSync, k256::ecdsa::SigningKey};
use alloy_signer_local::PrivateKeySigner;
use bytes::BufMut;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use timeboost_crypto::KeysetId;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Result, Unstructured};

use crate::{Bytes, Epoch, SeqNo, Timestamp};

const DOMAIN: &str = "TIMEBOOST_BID";

#[derive(Debug, Clone)]
pub enum BundleVariant {
    Regular(Bundle),
    Priority(SignedPriorityBundle),
}

/// A bundle contains a list of transactions (encrypted or unencrypted, both encoded as `Bytes`).
/// if `kid` is set to `Some<KeysetId>`, that signals an encrypted bundle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Bundle {
    chain: ChainId,
    epoch: Epoch,
    data: Bytes,
    kid: Option<KeysetId>,
    hash: [u8; 32],
}

impl Bundle {
    /// Constructor of bundle, when `kid.is_some()`, we assume `data` is encrypted.
    pub fn new(chain: ChainId, epoch: Epoch, data: Bytes, kid: Option<KeysetId>) -> Self {
        let mut this = Self {
            chain,
            epoch,
            data,
            kid,
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
        self.chain
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Returns true if the bundle is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.kid.is_some()
    }

    pub fn kid(&self) -> Option<KeysetId> {
        self.kid
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Set the data payload to some ciphertext bytes, encrypted under the specified keyset
    pub fn set_encrypted_data(&mut self, d: Bytes, kid: KeysetId) {
        self.data = d;
        self.kid = Some(kid);
        self.update_hash()
    }

    /// Set the data payload to un-encrypted, plaintext data.
    /// Use this at the end of the decryption phase
    pub fn set_data(&mut self, d: Bytes) {
        self.data = d;
        self.kid = None;
        self.update_hash();
    }

    #[cfg(feature = "arbitrary")]
    pub fn arbitrary(u: &mut Unstructured<'_>) -> Result<Self, InvalidTransaction> {
        use alloy_rlp::Encodable;

        let t: Transaction = loop {
            let candidate = Transaction::arbitrary(u)?;
            if let TxEnvelope::Eip4844(ref eip4844) = candidate.tx {
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
        let k = None;
        let b = Bundle::new(c, e, encoded.into(), k);

        Ok(b)
    }
}

impl Committable for Bundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Bundle")
            .field("chain", self.chain_id().commit())
            .field("epoch", self.epoch().commit())
            .var_size_field("data", self.data())
            .field("keysetid", self.kid().unwrap_or_default().commit())
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

    pub fn bundle_mut(&mut self) -> &mut Bundle {
        &mut self.bundle
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
        buf.extend_from_slice(&self.bundle().chain.0.to_be_bytes());
        buf.extend_from_slice(self.auction.0.0.as_slice());
        buf.extend_from_slice(&self.bundle().epoch.to_be_bytes());
        buf.extend_from_slice(&self.seqno.to_be_bytes());
        buf.extend_from_slice(&self.bundle().data);
        buf
    }

    pub fn sign(self, signer: Signer) -> Result<SignedPriorityBundle, Error> {
        use alloy_signer::Signer;
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
    pub fn validate(&self, epoch: Epoch, plc: Option<Address>) -> Result<(), ValidationError> {
        if self.bundle().chain != ChainId::default() {
            return Err(ValidationError::WrongChainId(self.bundle().chain));
        }

        // TODO: validate auction contract address
        if self.auction != Address::default() {
            return Err(ValidationError::WrongAuctionContract(self.auction));
        }

        if !(self.bundle().epoch == epoch || self.bundle().epoch == epoch + 1) {
            return Err(ValidationError::BadRoundNumber(self.bundle().epoch));
        }

        let Some(plc) = plc else {
            return Err(ValidationError::NoOnchainPLC);
        };

        let sender = self.sender()?;
        if sender.0 != plc.0 {
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

    pub fn set_data(&mut self, d: Bytes) {
        self.bundle.data = d;
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

#[derive(
    Debug, Default, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChainId(alloy_primitives::ChainId);

impl From<u64> for ChainId {
    fn from(value: u64) -> Self {
        ChainId(value)
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
    addr: Address,
    time: Timestamp,
}

// Boilerplate for ensuring trait compatibility
impl Typed2718 for Transaction {
    fn ty(&self) -> u8 {
        self.tx.ty()
    }
}

impl Encodable2718 for Transaction {
    fn encode_2718_len(&self) -> usize {
        self.tx.encode_2718_len()
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        self.tx.encode_2718(out);
    }

    fn type_flag(&self) -> Option<u8> {
        self.tx.type_flag()
    }

    fn encoded_2718(&self) -> Vec<u8> {
        self.tx.encoded_2718()
    }

    fn trie_hash(&self) -> B256 {
        self.tx.trie_hash()
    }

    fn seal(self) -> Sealed<Self> {
        let hash = self.tx.trie_hash();
        Sealed::new_unchecked(self, hash)
    }

    fn network_len(&self) -> usize {
        self.tx.network_len()
    }

    fn network_encode(&self, out: &mut dyn BufMut) {
        self.tx.network_encode(out);
    }
}

impl Transaction {
    pub fn decode(t: Timestamp, bytes: &[u8]) -> Result<Self, InvalidTransaction> {
        let mut buf = bytes;
        let tx = TxEnvelope::decode(&mut buf)?;
        Self::try_from((t, tx))
    }

    pub fn address(&self) -> &Address {
        &self.addr
    }

    #[cfg(feature = "arbitrary")]
    pub fn arbitrary(u: &mut Unstructured<'_>) -> Result<Self, InvalidTransaction> {
        let tx = TxEnvelope::arbitrary(u)?;
        let tm = Timestamp::arbitrary(u)?;
        Self::try_from((tm, tx))
    }
}

impl TryFrom<(Timestamp, TxEnvelope)> for Transaction {
    type Error = InvalidTransaction;

    fn try_from(val: (Timestamp, TxEnvelope)) -> Result<Self, Self::Error> {
        let addr = val.1.recover_signer()?;
        Ok(Self {
            tx: val.1,
            addr: addr.into(),
            time: val.0,
        })
    }
}

impl std::ops::Deref for Transaction {
    type Target = TxEnvelope;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

// Address wrapper
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Address(alloy_primitives::Address);

impl std::ops::Deref for Address {
    type Target = alloy_primitives::Address;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for Address {
    fn default() -> Self {
        Signer::default().0.address().into()
    }
}

impl From<alloy_primitives::Address> for Address {
    fn from(address: alloy_primitives::Address) -> Self {
        Address(address)
    }
}

impl From<Address> for alloy_primitives::Address {
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
pub struct Signature(alloy_signer::Signature);

impl std::ops::Deref for Signature {
    type Target = alloy_signer::Signature;
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
pub struct Signer(alloy_signer_local::PrivateKeySigner);

impl Default for Signer {
    fn default() -> Self {
        let private_key_bytes = [0x01; 32];
        let signing_key =
            SigningKey::from_bytes(&private_key_bytes.into()).expect("Invalid private key");
        let private_key_signer = PrivateKeySigner::from_signing_key(signing_key);

        Signer(private_key_signer)
    }
}

impl From<alloy_signer_local::PrivateKeySigner> for Signer {
    fn from(signer: alloy_signer_local::PrivateKeySigner) -> Self {
        Signer(signer)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidTransaction {
    #[error("invalid signature: {0}")]
    Signature(#[from] alloy_primitives::SignatureError),

    #[error("invalid rlp encoding: {0}")]
    Rlp(#[from] alloy_rlp::Error),

    #[cfg(feature = "arbitrary")]
    #[error("arbitrary error: {0}")]
    Arbitrary(#[from] arbitrary::Error),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("bundle chain ID {:?} does not match current chain ID: 0", .0)]
    WrongChainId(ChainId),

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
    use alloy_signer::k256::ecdsa::SigningKey;
    use alloy_signer_local::PrivateKeySigner;
    use ark_std::rand;
    use ssz::ssz_encode;

    use crate::{Epoch, SeqNo, bundle::Address};

    use super::{Bundle, ChainId, PriorityBundle, SignedPriorityBundle};

    #[test]
    fn test_verify() -> Result<(), Box<dyn std::error::Error>> {
        let epoch = Epoch::from(0);
        let private_key = SigningKey::random(&mut rand::thread_rng());
        let plc = PrivateKeySigner::from_signing_key(private_key);
        let bundle = sample_bundle(plc.clone()).unwrap();
        let plc_address = plc.address();
        let result = bundle.validate(epoch, Some(Address(plc_address)));
        assert_eq!(result, Ok(()));
        Ok(())
    }

    fn sample_bundle(plc: PrivateKeySigner) -> anyhow::Result<SignedPriorityBundle> {
        let mut rlp_encoded_txns = Vec::new();
        for _ in 0..5 {
            let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            rlp_encoded_txns.push(random_bytes);
        }
        let ssz_encoded_txns = ssz_encode(&rlp_encoded_txns);
        let bundle = Bundle::new(
            ChainId::default(),
            Epoch::default(),
            ssz_encoded_txns.into(),
            None,
        );
        let unsigned_priority = PriorityBundle::new(bundle, Address::default(), SeqNo::zero());

        let signed_priority = unsigned_priority.sign((plc).into());
        signed_priority.map_err(anyhow::Error::from)
    }
}
