use committable::Committable;

use timeboost_core::traits::comm::Comm;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::envelope::{Envelope, Validated};
use timeboost_core::types::message::Message;

enum Protocol {
    Proposal(Message<Validated>),
    Vote(Envelope<Message<Validated>, Validated>),
    Done(Certificate<Envelope<Message<Validated>, Validated>>),
}

pub struct Rbc {}
