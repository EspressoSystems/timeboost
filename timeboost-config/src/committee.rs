mod definition;

use core::fmt;
use std::path::Path;

use cliquenet::{Address, AddressableCommittee};
use multisig::{Committee, CommitteeId, PublicKey, x25519};
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::DkgEncKey;
use timeboost_types::{KeyStore, Timestamp};

use crate::{
    CERTIFIER_PORT_OFFSET, ConfigError, DECRYPTER_PORT_OFFSET, HTTP_API_PORT_OFFSET, read_toml,
};

pub use definition::{CommitteeDefinition, MemberFile};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeConfig {
    pub id: CommitteeId,
    pub effective: Timestamp,
    pub members: Vec<CommitteeMember>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub signing_key: PublicKey,
    pub dh_key: x25519::PublicKey,
    pub dkg_enc_key: DkgEncKey,
    pub address: Address,
    pub batchposter: Address,
}

impl CommitteeConfig {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        read_toml(path).await
    }

    pub fn committee(&self) -> Committee {
        Committee::new(
            self.id,
            self.members
                .iter()
                .enumerate()
                .map(|(i, m)| (i as u8, m.signing_key)),
        )
    }

    pub fn sailfish(&self) -> AddressableCommittee {
        let addrs = self
            .members
            .iter()
            .map(|m| (m.signing_key, m.dh_key, m.address.clone()));
        AddressableCommittee::new(self.committee(), addrs)
    }

    pub fn decrypt(&self) -> AddressableCommittee {
        let addrs = self.members.iter().map(|m| {
            (
                m.signing_key,
                m.dh_key,
                m.address.clone().with_offset(DECRYPTER_PORT_OFFSET),
            )
        });
        AddressableCommittee::new(self.committee(), addrs)
    }

    pub fn certify(&self) -> AddressableCommittee {
        let addrs = self.members.iter().map(|m| {
            (
                m.signing_key,
                m.dh_key,
                m.address.clone().with_offset(CERTIFIER_PORT_OFFSET),
            )
        });
        AddressableCommittee::new(self.committee(), addrs)
    }

    pub fn http_api(&self) -> AddressableCommittee {
        let addrs = self.members.iter().map(|m| {
            (
                m.signing_key,
                m.dh_key,
                m.address.clone().with_offset(HTTP_API_PORT_OFFSET),
            )
        });
        AddressableCommittee::new(self.committee(), addrs)
    }

    pub fn dkg_key_store(&self) -> KeyStore {
        let keys = self
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| (i as u8, m.dkg_enc_key.clone()));
        KeyStore::new(self.committee(), keys)
    }

    pub fn member(&self, key: &PublicKey) -> Option<&CommitteeMember> {
        self.members.iter().find(|m| m.signing_key == *key)
    }
}

impl fmt::Display for CommitteeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = toml::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&s)
    }
}

impl CommitteeMember {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        read_toml(path).await
    }
}
