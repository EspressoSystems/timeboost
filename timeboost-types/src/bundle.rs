use alloy_primitives::{Address, B256, PrimitiveSignature, keccak256};

use serde::{Deserialize, Serialize};
use timeboost_crypto::KeysetId;

use crate::{Bytes, Epoch, SeqNo, Transaction};

const DOMAIN: &str = "TIMEBOOST_BID";

#[derive(
    Debug, Default, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct ChainId(u32);

pub enum Bundle {
    Regular(RBundle),
    Priority(PBundle),
    Tx(Transaction),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RBundle {
    chain: ChainId,
    epoch: Epoch,
    auction: Address,
    data: Bytes,
    kid: Option<KeysetId>,
    // options: Option<Conditions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PBundle {
    chain: ChainId,
    epoch: Epoch,
    auction: Address,
    data: Bytes,
    kid: Option<KeysetId>,
    // options: Option<Conditions>,
    seqno: SeqNo,
    signature: Option<PrimitiveSignature>,
}

impl PBundle {
    // https://github.com/OffchainLabs/nitro/blob/1e16dc408d24a7784f19acd1e76a71daac528a22/timeboost/types.go#L206
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN.as_bytes());
        buf.extend_from_slice(&self.chain.0.to_be_bytes());
        buf.extend_from_slice(self.auction.as_ref());
        buf.extend_from_slice(&self.epoch.as_bytes());
        buf.extend_from_slice(&self.seqno.as_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }
}

impl PBundle {
    pub fn with_signature(&mut self, sig: PrimitiveSignature) {
        self.signature = Some(sig);
    }

    pub fn produce_hash(&self) -> B256 {
        let bundle_bytes = self.as_bytes();
        let length = bundle_bytes.len() as u32;
        let prefix = format!("\x19Ethereum Signed Message:\n{}", length);

        keccak256([prefix.into_bytes(), bundle_bytes].concat())
    }

    // https://github.com/OffchainLabs/nitro/blob/1e16dc408d24a7784f19acd1e76a71daac528a22/execution/gethexec/express_lane_service.go#L309
    pub fn validate(&self, epoch: Epoch, plc: Option<Address>) -> Result<(), ValidationError> {
        if self.chain != ChainId::default() {
            return Err(ValidationError::WrongChainId(self.chain));
        }

        if self.auction != Address::ZERO {
            return Err(ValidationError::WrongAuctionContract(self.auction));
        }

        if !(self.epoch == epoch || self.epoch == epoch + 1) {
            return Err(ValidationError::BadRoundNumber(self.epoch));
        }

        let Some(plc) = plc else {
            return Err(ValidationError::NoOnchainPLC);
        };

        let sender = self.sender()?;
        if *sender != *plc {
            return Err(ValidationError::NotPLC);
        }
        Ok(())
    }

    pub fn sender(&self) -> Result<Address, ValidationError> {
        let Some(signature) = self.signature else {
            return Err(ValidationError::UnableToRecoverAddress);
        };
        let msg = self.produce_hash();
        let recovered = signature.recover_address_from_msg(msg);
        recovered.map_err(|_| ValidationError::UnableToRecoverAddress)
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
    use alloy_primitives::{Address, keccak256};
    use alloy_signer::{SignerSync, k256::ecdsa::SigningKey};
    use alloy_signer_local::PrivateKeySigner;
    use ark_std::rand;
    use ssz::ssz_encode;

    use crate::{Epoch, SeqNo};

    use super::{ChainId, PBundle};

    #[tokio::test]
    async fn test_verify() -> Result<(), Box<dyn std::error::Error>> {
        let epoch = Epoch::from(0);
        let private_key = SigningKey::random(&mut rand::thread_rng());
        let plc = PrivateKeySigner::from_signing_key(private_key);
        let bundle = sample_bundle(&plc).await.unwrap();
        let plc_address = plc.address();
        let result = bundle.validate(epoch, Some(plc_address));
        assert_eq!(result, Ok(()));
        Ok(())
    }

    async fn sample_bundle(plc: &PrivateKeySigner) -> anyhow::Result<PBundle> {
        let mut rlp_encoded_txns = Vec::new();
        for _ in 0..5 {
            let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            rlp_encoded_txns.push(random_bytes);
        }
        let ssz_encoded_txns = ssz_encode(&rlp_encoded_txns);

        let mut bundle = PBundle {
            chain: ChainId::default(),
            epoch: Epoch::default(),
            auction: Address::ZERO,
            data: ssz_encoded_txns.into(),
            kid: None,
            seqno: SeqNo::default(),
            signature: None,
        };
        let bundle_bytes = bundle.as_bytes();
        let length = bundle_bytes.len() as u32;
        let prefix = format!("\x19Ethereum Signed Message:\n{}", length);

        let hash = keccak256([prefix.into_bytes(), bundle_bytes].concat());

        let Ok(signature) = plc.sign_message_sync(hash.as_slice()) else {
            return Err(anyhow::anyhow!("Failed to sign the message"));
        };
        bundle.with_signature(signature);

        Ok(bundle)
    }
}
