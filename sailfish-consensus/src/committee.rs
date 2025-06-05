use multisig::{Certificate, Envelope, Validated, VoteAccumulator};
use sailfish_types::{Handover, HandoverMessage};

/// Handover vote accumulation and buffer.
pub(crate) struct Handovers {
    /// Collect handover messages to form a certificate.
    pub(crate) votes: Option<VoteAccumulator<Handover>>,

    /// Buffer of handover messages.
    ///
    /// In case where handover messages arrive before we know about the next
    /// committee (which can only happend for members of the current committee),
    /// we buffer them and apply them as soon as `add_committee` is called.
    pub(crate) buffer: Vec<Envelope<HandoverMessage, Validated>>,

    /// Buffer of handover certificate.
    ///
    /// Same reason, why we have `buffer`, but for the handover certificate,
    /// of which there is only one.
    pub(crate) cert: Option<Certificate<Handover>>,
}
