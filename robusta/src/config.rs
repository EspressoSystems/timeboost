use std::{iter::repeat, time::Duration};

use bon::Builder;
use url::{ParseError, Url};

const NUM_DELAYS: usize = 5;

#[derive(Debug, Clone, Builder)]
pub struct Config {
    /// Log label.
    pub(crate) label: String,

    /// Espresso network base URL.
    #[builder(with = |s: &str| -> Result<_, ParseError> { Url::parse(s) })]
    pub(crate) base_url: Url,

    /// Espresso network websocket base URL.
    #[builder(with = |s: &str| -> Result<_, ParseError> { Url::parse(s) })]
    pub(crate) wss_base_url: Url,

    /// The sequence of delays between successive requests.
    ///
    /// The last value is repeated forever.
    #[builder(default = [1, 3, 5, 10, 15])]
    pub(crate) delays: [u8; NUM_DELAYS],
}

impl Config {
    pub fn delay_iter(&self) -> impl Iterator<Item = Duration> + use<> {
        self.delays
            .into_iter()
            .chain(repeat(self.delays[NUM_DELAYS - 1]))
            .map(|n| Duration::from_secs(n.into()))
    }
}
