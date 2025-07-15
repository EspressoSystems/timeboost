use std::str::from_utf8;

use espresso_types::{Header, NamespaceId};
use futures::{SinkExt, TryStreamExt};
use reqwest::header::LOCATION;
use tokio::{net::TcpStream, time::sleep};
use tokio_tungstenite::tungstenite::{self, Message, client::IntoClientRequest};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tracing::{debug, warn};

use crate::{Config, types::Height};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn watch<H, N>(cfg: &Config, height: H, nsid: N) -> Result<Header, WatchError>
where
    H: Into<Height>,
    N: Into<Option<NamespaceId>>,
{
    let height = height.into();
    let nsid = nsid.into();

    let mut ws = connect(cfg, height).await?;

    while let Some(m) = ws.try_next().await? {
        match m {
            Message::Binary(_) => {
                debug!("bytes received")
            }
            Message::Text(text) => match serde_json::from_str::<Header>(text.as_str()) {
                Ok(hdr) => {
                    if let Some(id) = nsid {
                        if hdr.ns_table().find_ns_id(&id).is_some() {
                            return Ok(hdr);
                        } else {
                            debug!(height = %hdr.height(), "namespace id not found");
                        }
                    } else {
                        return Ok(hdr);
                    }
                }
                Err(err) => {
                    warn!(%err, "could not read text frame as header")
                }
            },
            Message::Ping(bytes) => {
                debug!("ping received");
                ws.send(Message::Pong(bytes)).await?
            }
            Message::Pong(_) => {
                debug!("unexpected pong")
            }
            Message::Close(frame) => {
                if let Some(f) = frame {
                    warn!(code = ?f.code, reason = %f.reason.as_str(), "connection closed");
                }
                return Err(WatchError::Closed);
            }
            Message::Frame(_) => unreachable!("tungestnite does not produce this while reading"),
        }
    }

    Err(WatchError::Closed)
}

async fn connect(cfg: &Config, h: Height) -> Result<Ws, WatchError> {
    let mut url = cfg
        .wss_base_url
        .join(&format!("/availability/stream/headers/{h}"))?;

    let mut delay = cfg.delay_iter();
    let mut redirect = 0;

    while redirect < cfg.max_redirects {
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
                    redirect += 1;
                    url.set_path(path);
                    debug!(%url, "following redirection");
                    continue;
                }
                warn!(%url, ?r, "failed to connect")
            }
            Err(err) => {
                warn!(%url, %err, "failed to connect")
            }
        }
        let d = delay.next().expect("infinite delay sequence");
        sleep(d).await
    }

    Err(WatchError::TooManyRedirects)
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("websocket error: {0}")]
    Ws(#[from] tungstenite::Error),

    #[error("no tls")]
    NoTls,

    #[error("connection closed")]
    Closed,

    #[error("too many redirects")]
    TooManyRedirects,
}
