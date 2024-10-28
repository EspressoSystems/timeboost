use hotshot_types::data::ViewNumber;
use sailfish::types::message::Message;

pub struct Interceptor {
    msg_modifier: Box<dyn Fn(&Message) -> Message>,
    modify_at_round: ViewNumber,
}

impl Interceptor {
    pub(crate) fn new(
        msg_modifier: Box<dyn Fn(&Message) -> Message>,
        modify_at_round: ViewNumber,
    ) -> Self {
        Self {
            msg_modifier,
            modify_at_round,
        }
    }
    pub(crate) fn intercept_message(&self, msg: Message) -> Message {
        let round = msg.round();
        if self.modify_at_round == round {
            let new = (self.msg_modifier)(&msg);
            return new;
        }

        msg
    }
}
