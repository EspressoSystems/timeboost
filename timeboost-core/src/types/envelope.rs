use std::{fmt, hash::Hash, marker::PhantomData};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use hotshot::types::SignatureKey;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use tracing::warn;

use crate::types::{committee::StaticCommittee, PublicKey, Signature};

use super::Keypair;

/// Marker type to denote envelopes whose signature has not been validated.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Unchecked {}

/// Marker type to denote envelopes whose signature has been validated.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
pub enum Validated {}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
pub struct Envelope<D: Committable, S> {
    data: D,
    commitment: Commitment<D>,
    signature: Signature,
    signing_key: PublicKey,
    #[serde(skip)]
    _marker: PhantomData<fn(S)>,
}

impl<D: Committable> Envelope<D, Validated> {
    /// Create a (validated) envelope by signing data with a private key.
    pub fn signed(d: D, keypair: &Keypair) -> Self {
        let c = d.commit();
        let s = keypair.sign(c.as_ref());
        Self {
            data: d,
            commitment: c,
            signature: s,
            signing_key: *keypair.public_key(),
            _marker: PhantomData,
        }
    }
}

impl<D: Committable, S> Envelope<D, S> {
    /// Is the signature of this envelope valid?
    pub fn is_valid(&self, membership: &StaticCommittee) -> bool {
        membership.committee().contains(&self.signing_key)
            && self.data.commit() == self.commitment
            && self
                .signing_key
                .validate(&self.signature, self.commitment.as_ref())
    }

    /// Transition from an unchecked envelope to a validated one.
    ///
    /// This checks that the signature of the envelope is valid and represents
    /// the only way to get a validated envelope from an unchecked one.
    pub fn validated(self, membership: &StaticCommittee) -> Option<Envelope<D, Validated>> {
        if !self.is_valid(membership) {
            warn!(from = %self.signing_key, commit = %self.commitment, "invalid envelope");
            return None;
        }
        Some(Envelope {
            data: self.data,
            commitment: self.commitment,
            signature: self.signature,
            signing_key: self.signing_key,
            _marker: PhantomData,
        })
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signing_key(&self) -> &PublicKey {
        &self.signing_key
    }

    pub fn commitment(&self) -> Commitment<D> {
        self.commitment
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn into_data(self) -> D {
        self.data
    }
}

impl<'de, T, S> Deserialize<'de> for Envelope<T, S>
where
    T: Committable + Deserialize<'de>,
    S: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Data,
            Commitment,
            Signature,
            SigningKey,
        }

        struct EnvelopeVisitor<T, S>(PhantomData<fn(T, S)>);

        impl<'de, T, S> Visitor<'de> for EnvelopeVisitor<T, S>
        where
            T: Committable + Deserialize<'de>,
            S: Deserialize<'de>,
        {
            type Value = Envelope<T, S>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Envelope")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Envelope<T, S>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let data = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let commitment = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let signature = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let signing_key = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                Ok(Envelope {
                    data,
                    commitment,
                    signature,
                    signing_key,
                    _marker: PhantomData,
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<Envelope<T, S>, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut data = None;
                let mut commitment = None;
                let mut signature = None;
                let mut signing_key = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Data => {
                            if data.is_some() {
                                return Err(de::Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value()?);
                        }
                        Field::Commitment => {
                            if commitment.is_some() {
                                return Err(de::Error::duplicate_field("commitment"));
                            }
                            commitment = Some(map.next_value()?);
                        }
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        }
                        Field::SigningKey => {
                            if signing_key.is_some() {
                                return Err(de::Error::duplicate_field("signing_key"));
                            }
                            signing_key = Some(map.next_value()?);
                        }
                    }
                }
                let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
                let commitment =
                    commitment.ok_or_else(|| de::Error::missing_field("commitment"))?;
                let signature = signature.ok_or_else(|| de::Error::missing_field("signature"))?;
                let signing_key =
                    signing_key.ok_or_else(|| de::Error::missing_field("signing_key"))?;
                Ok(Envelope {
                    data,
                    commitment,
                    signature,
                    signing_key,
                    _marker: PhantomData,
                })
            }
        }

        const FIELDS: &[&str] = &["data", "commitment", "signature", "signing_key"];
        deserializer.deserialize_struct("Envelope", FIELDS, EnvelopeVisitor(PhantomData))
    }
}

impl<D: Committable> Committable for Envelope<D, Validated> {
    fn commit(&self) -> Commitment<Self> {
        let sig = bincode::serialize(&self.signature).expect("serializing signature never fails");
        RawCommitmentBuilder::new("Envelope")
            .field("data", self.data.commit())
            .field("commitment", self.commitment)
            .var_size_field("signature", &sig)
            .var_size_field("signing_key", &self.signing_key.to_bytes())
            .finalize()
    }
}
