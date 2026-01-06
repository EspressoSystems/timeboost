mod certifier;
mod config;
mod submit;

#[cfg(feature = "metrics")]
mod metrics;

pub use robusta;

pub use certifier::{Certifier, CertifierDown, CertifierError, Handle};
pub use config::{CertifierConfig, CertifierConfigBuilder};
pub use config::{SubmitterConfig, SubmitterConfigBuilder};
pub use submit::{SenderTaskDown, Submitter};

#[cfg(feature = "metrics")]
pub mod time_series {
    pub const VERIFIED: &str = "verified";
    pub const CERTIFY_START: &str = "certify_start";
    pub const CERTIFY_END: &str = "certify_end";
}
