use alloy::consensus::TxEnvelope;

use alloy_rlp::Decodable;
use alloy_signer::{Error, SignerSync, k256::ecdsa::SigningKey};
use alloy_signer_local::PrivateKeySigner;
use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};
use timeboost_crypto::KeysetId;

use crate::{Bytes, Epoch, SeqNo};

const DOMAIN: &str = "TIMEBOOST_BID";

pub enum BundleVariant {
    Regular(Bundle),
    Priority(PriorityBundle<Signed>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Bundle {
    chain: ChainId,
    epoch: Epoch,
    data: Bytes,
    kid: Option<KeysetId>,
    hash: [u8; 32],
}

impl Bundle {
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

    pub fn kid(&self) -> Option<KeysetId> {
        self.kid
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn set_data(&mut self, d: Bytes) {
        self.data = d;
        self.update_hash()
    }
}

impl Committable for Bundle {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("PriorityBundle")
            .field("chain", self.chain_id().commit())
            .field("epoch", self.epoch().commit())
            .var_size_field("data", self.data())
            .field("keysetid", self.kid().unwrap_or_default().commit())
            .finalize()
    }
}

pub trait State {}
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signed {
    signature: Signature,
}
pub struct Unsigned {}
impl State for Signed {}
impl State for Unsigned {}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PriorityBundle<S: State> {
    bundle: Bundle,
    auction: Address,
    seqno: SeqNo,
    hash: [u8; 32],
    signed: S,
}

impl<S: State> PriorityBundle<S> {
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
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN.as_bytes());
        buf.extend_from_slice(&self.bundle().chain.0.to_be_bytes());
        buf.extend_from_slice(self.auction.0.0.as_slice());
        buf.extend_from_slice(&self.bundle().epoch.as_bytes());
        buf.extend_from_slice(&self.seqno.as_bytes());
        buf.extend_from_slice(&self.bundle().data);
        buf
    }
}

impl PriorityBundle<Unsigned> {
    pub fn new(bundle: Bundle, auction: Address, seqno: SeqNo) -> Self {
        Self {
            auction,
            seqno,
            hash: [0; 32],
            bundle,
            signed: Unsigned {},
        }
    }

    pub fn sign(self, signer: Signer) -> Result<PriorityBundle<Signed>, Error> {
        use alloy_signer::Signer;
        let signer = signer.0.with_chain_id(Some(self.bundle().chain_id().0));
        signer.sign_message_sync(&self.as_bytes()).map(|signature| {
            PriorityBundle::<Signed>::new(
                self.bundle.clone(),
                self.auction,
                self.seqno,
                Signature(signature),
            )
        })
    }
}

impl PriorityBundle<Signed> {
    pub fn new(bundle: Bundle, auction: Address, seqno: SeqNo, signature: Signature) -> Self {
        let mut this = Self {
            auction,
            seqno,
            hash: [0; 32],
            bundle,
            signed: Signed { signature },
        };
        this.update_hash();
        this
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn signature(&self) -> &Signature {
        &self.signed.signature
    }

    // https://github.com/OffchainLabs/nitro/blob/1e16dc408d24a7784f19acd1e76a71daac528a22/execution/gethexec/express_lane_service.go#L309
    pub fn validate(&self, epoch: Epoch, plc: Option<Address>) -> Result<(), ValidationError> {
        if self.bundle().chain != ChainId::default() {
            return Err(ValidationError::WrongChainId(self.bundle().chain));
        }

        // TODO: validate auction contract address
        if self.auction != Address::zero() {
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

    pub fn sender(&self) -> Result<Address, ValidationError> {
        let msg = self.as_bytes();
        let recovered = self.signature().recover_address_from_msg(msg);
        Ok(Address(
            recovered.map_err(|_| ValidationError::UnableToRecoverAddress)?,
        ))
    }

    pub fn set_data(&mut self, d: Bytes) {
        self.bundle.data = d;
        self.update_hash()
    }

    fn update_hash(&mut self) {
        let digest = self.commit();
        self.hash = digest.into();
    }
}

impl Committable for PriorityBundle<Signed> {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("PriorityBundle")
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
pub struct ChainId(alloy::primitives::ChainId);

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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Transaction(TxEnvelope);

impl Transaction {
    pub fn decode(bytes: &[u8]) -> Result<Self, alloy_rlp::Error> {
        let mut buf = bytes;
        TxEnvelope::decode(&mut buf).map(Transaction)
    }
}

impl std::ops::Deref for Transaction {
    type Target = TxEnvelope;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Transaction {
    pub fn new(tx: TxEnvelope) -> Self {
        Transaction(tx)
    }

    pub fn tx(&self) -> &TxEnvelope {
        &self.0
    }
}

// Address wrapper
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(alloy::primitives::Address);

impl Address {
    pub fn zero() -> Self {
        Address(alloy::primitives::Address::ZERO)
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
pub struct Signer(alloy::signers::local::PrivateKeySigner);

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

    use super::{Bundle, ChainId, PriorityBundle, Signed, Unsigned};

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

    fn sample_bundle(plc: PrivateKeySigner) -> anyhow::Result<PriorityBundle<Signed>> {
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
        let unsigned_priority =
            PriorityBundle::<Unsigned>::new(bundle, Address::zero(), SeqNo::zero());

        let signed_priority = unsigned_priority.sign((plc).into());
        signed_priority.map_err(anyhow::Error::from)
    }
}
