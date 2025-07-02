pub mod gas_estimator;

// Definition of SailfishBlock type for use within the project
pub mod sailfish {
    use committable::{Commitment, Committable, RawCommitmentBuilder};
    use sailfish_types::{ConsensusTime, HasTime, Timestamp};
    use serde::{Deserialize, Serialize};
    use std::ops::Deref;
    
    /// Represents a Sailfish block for use in gas_estimator
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SailfishBlock {
        time: Timestamp,
        transactions: Vec<Vec<u8>>,
    }
    
    impl SailfishBlock {
        pub fn new(time: Timestamp, transactions: Vec<Vec<u8>>) -> Self {
            Self { time, transactions }
        }
        
        pub fn transactions(&self) -> &[Vec<u8>] {
            &self.transactions
        }
    }
    
    impl HasTime for SailfishBlock {
        fn time(&self) -> Timestamp {
            self.time
        }
    }
    
    impl Committable for SailfishBlock {
        fn commit(&self) -> Commitment<Self> {
            RawCommitmentBuilder::new("SailfishBlock")
                .field("time", &self.time)
                .field("transactions", &self.transactions)
                .finalize()
        }
    }
} 
