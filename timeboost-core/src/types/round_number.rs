use committable::{Commitment, Committable, RawCommitmentBuilder};
use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoundNumber(ViewNumber);

impl From<ViewNumber> for RoundNumber {
    fn from(val: ViewNumber) -> Self {
        Self(val)
    }
}

impl RoundNumber {
    pub fn new(val: u64) -> Self {
        RoundNumber(ViewNumber::new(val))
    }

    pub fn u64(&self) -> u64 {
        *self.0
    }

    pub fn genesis() -> Self {
        RoundNumber(ViewNumber::genesis())
    }
}

impl std::ops::Add<u64> for RoundNumber {
    type Output = RoundNumber;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
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

impl std::ops::Sub<u64> for RoundNumber {
    type Output = RoundNumber;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl Committable for RoundNumber {
    fn commit(&self) -> Commitment<Self> {
        let builder = RawCommitmentBuilder::new("Round Number Commitment");
        builder.u64(*self.0).finalize()
    }
}

impl std::fmt::Display for RoundNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
