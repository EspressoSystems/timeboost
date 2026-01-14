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
