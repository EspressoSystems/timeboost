mod certifier;
mod config;
mod metrics;
mod submit;

pub use robusta;

pub use certifier::{Certifier, CertifierDown, CertifierError, Handle};
pub use config::{CertifierConfig, CertifierConfigBuilder};
pub use config::{SubmitterConfig, SubmitterConfigBuilder};
pub use submit::{SenderTaskDown, Submitter};

#[cfg(feature = "times")]
pub mod time_series {
    pub const VERIFIED: &'static str = "verified";
    pub const CERTIFY_START: &'static str = "certify_start";
    pub const CERTIFY_END: &'static str = "certify_end";
}
