use std::str::from_utf8;

use bytes::Bytes;
use espresso_types::{Header, NamespaceId};
use futures::{SinkExt, StreamExt};
use reqwest::header::LOCATION;
use tokio::{net::TcpStream, time::sleep};
use tokio_tungstenite::tungstenite::{self, Message, client::IntoClientRequest};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tracing::{debug, warn};

use crate::{Config, types::Height};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
pub struct Watcher {
    config: Config,
    height: Height,
    namespace: Option<NamespaceId>,
    websocket: Option<Ws>,
    ping: Option<Bytes>,
}

impl Watcher {
    pub fn new<H, N>(cfg: Config, height: H, nsid: N) -> Self
    where
        H: Into<Height>,
        N: Into<Option<NamespaceId>>,
    {
        Self {
            config: cfg,
            height: height.into(),
            namespace: nsid.into(),
            websocket: None,
            ping: None,
        }
    }

    pub async fn next(&mut self) -> Header {
        'main: loop {
            let ws = if let Some(w) = &mut self.websocket {
                w
            } else {
                let mut d = self.config.delay_iter();
                let w = loop {
                    match self.connect().await {
                        Ok(w) => break w,
                        Err(err) => {
                            warn!(%err, "failed to connect");
                            sleep(d.next().expect("infinite delay sequence")).await
                        }
                    }
                };
                self.websocket = Some(w);
                self.websocket.as_mut().expect("self.websocket.is_some()")
            };

            if let Some(bytes) = &self.ping {
                if let Err(err) = ws.send(Message::Pong(bytes.clone())).await {
                    warn!(%err, "failed to answer ping");
                    self.ping = None;
                    self.websocket = None;
                    continue 'main;
                } else {
                    self.ping = None
                }
            }

            loop {
                match ws.next().await {
                    Some(Ok(Message::Binary(_))) => {
                        debug!("bytes received");
                    }
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<Header>(text.as_str()) {
                            Ok(hdr) => {
                                if let Some(id) = &self.namespace {
                                    if hdr.ns_table().find_ns_id(id).is_some() {
                                        self.height = hdr.height().into();
                                        return hdr;
                                    } else {
                                        debug!(height = %hdr.height(), "namespace id not found");
                                    }
                                } else {
                                    self.height = hdr.height().into();
                                    return hdr;
                                }
                            }
                            Err(err) => {
                                warn!(%err, "could not read text frame as header");
                            }
                        }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        debug!("ping received");
                        self.ping = Some(bytes.clone());
                        if let Err(err) = ws.send(Message::Pong(bytes)).await {
                            warn!(%err, "failed to answer ping");
                            self.ping = None;
                            self.websocket = None;
                            continue 'main;
                        } else {
                            self.ping = None
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        debug!("unexpected pong");
                    }
                    Some(Ok(Message::Close(frame))) => {
                        if let Some(f) = frame {
                            warn!(code = ?f.code, reason = %f.reason.as_str(), "connection closed");
                        }
                        self.websocket = None;
                        continue 'main;
                    }
                    Some(Ok(Message::Frame(_))) => {
                        // Tungstenite does not produce `Message::Frame` while reading.
                        debug!("unexpected frame");
                    }
                    Some(Err(err)) => {
                        warn!(%err, "websocket error");
                        self.websocket = None;
                        continue 'main;
                    }
                    None => {
                        warn!("websocket stream ended");
                        self.websocket = None;
                        continue 'main;
                    }
                }
            }
        }
    }

    async fn connect(&self) -> Result<Ws, WatchError> {
        let mut url = self
            .config
            .wss_base_url
            .join(&format!("availability/stream/headers/{}", self.height))?;

        loop {
            debug!(%url, "connecting");
            let r = (&url).into_client_request()?;
            match connect_async(r).await {
                Ok((w, _)) => {
                    debug!(%url, "connection established");
                    return Ok(w);
                }
                Err(tungstenite::Error::Http(r)) => {
                    if r.status().is_redirection()
                        && let Some(loc) = r.headers().get(LOCATION)
                        && let Ok(path) = from_utf8(loc.as_bytes())
                    {
                        url.set_path(path);
                        debug!(%url, "following redirection");
                        continue;
                    }
                    warn!(%url, ?r, "failed to connect")
                }
                Err(err) => {
                    warn!(%url, %err, "failed to connect");
                    return Err(err.into());
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("websocket error: {0}")]
    Ws(#[from] tungstenite::Error),
}
