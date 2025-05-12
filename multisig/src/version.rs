use std::fmt;
use std::ops::Deref;

use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version(u32);

impl Version {
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

impl From<u32> for Version {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<Version> for u64 {
    fn from(val: Version) -> Self {
        val.0.into()
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Committable for Version {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Version").u32(self.0).finalize()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Versioned<T>(Version, T);

impl<T> Versioned<T> {
    pub fn new<V: Into<Version>>(v: V, x: T) -> Self {
        Self(v.into(), x)
    }

    pub fn version(&self) -> Version {
        self.0
    }

    pub fn into_data(self) -> T {
        self.1
    }
}

impl<T> Deref for Versioned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl<T> From<(Version, T)> for Versioned<T> {
    fn from((v, d): (Version, T)) -> Self {
        Versioned(v, d)
    }
}

impl<T> From<Versioned<T>> for (Version, T) {
    fn from(Versioned(v, d): Versioned<T>) -> Self {
        (v, d)
    }
}

impl<T: Committable> Committable for Versioned<T> {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Versioned")
            .field("version", self.0.commit())
            .field("data", self.1.commit())
            .finalize()
    }
}
