use committable::{Commitment, Committable, RawCommitmentBuilder};
use serde::{Deserialize, Serialize};

#[derive(
    Copy, Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct RoundNumber(u64);

impl RoundNumber {
    pub fn new(val: u64) -> Self {
        Self(val)
    }

    pub fn u64(&self) -> u64 {
        self.0
    }

    /// Convert to a `i64` for postgres.
    pub fn i64(&self) -> i64 {
        self.0 as i64
    }

    pub fn genesis() -> Self {
        Self::new(0)
    }

    pub fn is_genesis(self) -> bool {
        self == Self::genesis()
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<u64>()
    }
}

impl From<u64> for RoundNumber {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<i64> for RoundNumber {
    fn from(val: i64) -> Self {
        Self(val as u64)
    }
}

impl From<i32> for RoundNumber {
    fn from(val: i32) -> Self {
        Self(val as u64)
    }
}

impl From<RoundNumber> for u64 {
    fn from(val: RoundNumber) -> Self {
        val.0
    }
}

impl std::ops::Add for RoundNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl std::ops::Add<u64> for RoundNumber {
    type Output = RoundNumber;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::AddAssign for RoundNumber {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl std::ops::AddAssign<u64> for RoundNumber {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl std::ops::Deref for RoundNumber {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Sub for RoundNumber {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl std::ops::Sub<u64> for RoundNumber {
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

impl std::fmt::Display for RoundNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
