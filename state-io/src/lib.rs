#[cfg(feature = "dynamodb")]
mod dynamodb;
#[cfg(feature = "fs")]
mod fs;
#[cfg(feature = "no-io")]
mod noio;

#[cfg(feature = "dynamodb")]
pub use dynamodb::StateIo;

#[cfg(feature = "fs")]
pub use fs::StateIo;

#[cfg(feature = "no-io")]
pub use noio::StateIo;

pub mod env {
    #[cfg(feature = "dynamodb")]
    pub const TIMEBOOST_DYNAMODB_TABLE: &str = "TIMEBOOST_DYNAMODB_TABLE";

    #[cfg(any(feature = "fs", feature = "dynamodb"))]
    pub const TIMEBOOST_STAMP: &str = "TIMEBOOST_STAMP";
}
