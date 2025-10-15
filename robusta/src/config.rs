use std::{iter::repeat, num::NonZeroUsize, time::Duration};

use bon::Builder;
use url::Url;

const NUM_DELAYS: NonZeroUsize = NonZeroUsize::new(5).expect("5 > 0");

#[derive(Debug, Clone, Builder)]
pub struct Config {
    /// Log label.
    #[builder(into)]
    pub(crate) label: String,

    /// Espresso network base URL.
    pub(crate) base_url: Url,

    /// Espresso network builder base URL.
    pub(crate) builder_base_url: Url,

    /// Espresso network websocket base URL.
    pub(crate) wss_base_url: Url,

    /// The sequence of delays between successive requests.
    ///
    /// The last value is repeated forever.
    #[builder(default = [1, 3, 5, 10, 15])]
    pub(crate) delays: [u8; NUM_DELAYS.get()],

    /// Submitter should connect only with https?
    #[builder(default = true)]
    pub(crate) https_only: bool,
}

impl Config {
    pub fn with_websocket_base_url(&self, u: Url) -> Self {
        let mut c = self.clone();
        c.wss_base_url = u;
        c
    }

    pub fn delay_iter(&self) -> impl Iterator<Item = Duration> + use<> {
        self.delays
            .into_iter()
            .chain(repeat(self.delays[NUM_DELAYS.get() - 1]))
            .map(|n| Duration::from_secs(n.into()))
    }
}
