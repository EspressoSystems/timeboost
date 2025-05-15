use std::fmt;
use std::ops::{Add, AddAssign, Deref, Sub};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::Indexed;
use serde::{Deserialize, Serialize};

/// The sailfish genesis round number.
pub const GENESIS_ROUND: RoundNumber = RoundNumber::new(0);

/// A sailfish round number.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoundNumber(u64);

impl RoundNumber {
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    pub fn u64(&self) -> u64 {
        self.0
    }

    pub fn genesis() -> Self {
        GENESIS_ROUND
    }

    pub fn is_genesis(self) -> bool {
        self == GENESIS_ROUND
    }
}

impl Indexed for RoundNumber {
    type Index = Self;

    fn index(&self) -> Self::Index {
        *self
    }
}

impl From<u64> for RoundNumber {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<RoundNumber> for u64 {
    fn from(val: RoundNumber) -> Self {
        val.0
    }
}

impl Add for RoundNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<u64> for RoundNumber {
    type Output = RoundNumber;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl AddAssign for RoundNumber {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl AddAssign<u64> for RoundNumber {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Deref for RoundNumber {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Sub for RoundNumber {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub<u64> for RoundNumber {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl Committable for RoundNumber {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Round Number Commitment");
        builder.u64(self.0).finalize()
    }
}

impl fmt::Display for RoundNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
