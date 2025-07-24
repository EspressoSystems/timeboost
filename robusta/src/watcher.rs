use std::future::ready;
use std::str::from_utf8;

use espresso_types::{Header, NamespaceId};
use futures::{SinkExt, Stream, StreamExt, stream};
use reqwest::header::LOCATION;
use tokio::{net::TcpStream, time::sleep};
use tokio_tungstenite::tungstenite::{self, Message, client::IntoClientRequest};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tracing::{debug, warn};

use crate::{Config, types::Height};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn watch<H, N>(
    cfg: &Config,
    height: H,
    nsid: N,
) -> Result<impl Stream<Item = Header> + use<H, N>, WatchError>
where
    H: Into<Height>,
    N: Into<Option<NamespaceId>>,
{
    let height = height.into();
    let nsid = nsid.into();

    let ws = connect(cfg, height).await?;
    let ws = stream::unfold(ws, move |mut ws| async move {
        match ws.next().await? {
            Ok(Message::Binary(_)) => {
                debug!("bytes received");
                Some((None, ws))
            }
            Ok(Message::Text(text)) => match serde_json::from_str::<Header>(text.as_str()) {
                Ok(hdr) => {
                    if let Some(id) = nsid {
                        if hdr.ns_table().find_ns_id(&id).is_some() {
                            Some((Some(hdr), ws))
                        } else {
                            debug!(height = %hdr.height(), "namespace id not found");
                            Some((None, ws))
                        }
                    } else {
                        Some((Some(hdr), ws))
                    }
                }
                Err(err) => {
                    warn!(%err, "could not read text frame as header");
                    None
                }
            },
            Ok(Message::Ping(bytes)) => {
                debug!("ping received");
                if let Err(err) = ws.send(Message::Pong(bytes)).await {
                    warn!(%err, "failed to answer ping")
                }
                Some((None, ws))
            }
            Ok(Message::Pong(_)) => {
                debug!("unexpected pong");
                Some((None, ws))
            }
            Ok(Message::Close(frame)) => {
                if let Some(f) = frame {
                    warn!(code = ?f.code, reason = %f.reason.as_str(), "connection closed");
                }
                None
            }
            Ok(Message::Frame(_)) => {
                unreachable!("tungstenite does not produce this while reading")
            }
            Err(err) => {
                warn!(%err, "websocket error");
                None
            }
        }
    });
    Ok(ws.filter_map(ready))
}

async fn connect(cfg: &Config, h: Height) -> Result<Ws, WatchError> {
    let mut url = cfg
        .wss_base_url
        .join(&format!("availability/stream/headers/{h}"))?;

    let mut delay = cfg.delay_iter();

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
                warn!(%url, %err, "failed to connect")
            }
        }
        let d = delay.next().expect("infinite delay sequence");
        sleep(d).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("websocket error: {0}")]
    Ws(#[from] tungstenite::Error),
}
