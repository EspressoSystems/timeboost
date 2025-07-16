mod certifier;
mod config;
mod submit;

pub use certifier::{Certifier, CertifierDown, CertifierError, Handle};
pub use config::{CertifierConfig, CertifierConfigBuilder};
pub use config::{SubmitterConfig, SubmitterConfigBuilder};
pub use robusta;
pub use submit::Submitter;

use std::time::Duration;

use robusta::Height;
use timeboost_types::CertifiedBlock;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

pub async fn submit(mut s: Submitter<Height>, mut rx: UnboundedReceiver<CertifiedBlock>) {
    enum State {
        Submit(bool),
        Verify,
    }

    let d = Duration::from_secs(30);

    'main: while let Some(cb) = rx.recv().await {
        let mut state = State::Submit(false);
        loop {
            match state {
                State::Submit(force) => match timeout(d, s.submit(&cb, force)).await {
                    Ok(()) => state = State::Verify,
                    Err(e) => {
                        let _: Elapsed = e;
                        state = State::Submit(true)
                    }
                },
                State::Verify => match timeout(d, s.verify(&cb)).await {
                    Ok(Ok(())) => continue 'main,
                    Ok(Err(())) => state = State::Submit(true),
                    Err(e) => {
                        let _: Elapsed = e;
                        state = State::Submit(true)
                    }
                },
            }
        }
    }
}
