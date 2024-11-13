use std::io::{self, ErrorKind};

use anyhow::Result;
use async_lock::RwLock;
use async_trait::async_trait;
use committable::Committable;
use futures::FutureExt;
use tide_disco::{error::ServerError, Api, App, StatusCode, Url};
use timeboost_core::types::{
    event::{TimeboostEventType, TimeboostStatusEvent},
    transaction::Transaction,
};
use tokio::sync::mpsc::Sender;
use vbs::version::{StaticVersion, StaticVersionType};

pub struct TimeboostApiState {
    app_tx: Sender<TimeboostStatusEvent>,
}

#[async_trait]
pub trait TimeboostApi {
    async fn submit(&self, tx: Transaction) -> Result<(), ServerError>;
}

impl TimeboostApiState {
    pub fn new(app_tx: Sender<TimeboostStatusEvent>) -> Self {
        Self { app_tx }
    }

    pub async fn run(self, url: Url) -> io::Result<()> {
        let api = define_api::<StaticVersion<0, 1>>()
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;
        let state = RwLock::new(self);
        let mut app = App::<RwLock<TimeboostApiState>, ServerError>::with_state(state);
        app.register_module("timeboost-api", api)
            .expect("Failed to register timeboost-api");
        app.serve(url, StaticVersion::<0, 1> {}).await
    }
}

#[async_trait]
impl TimeboostApi for TimeboostApiState {
    async fn submit(&self, tx: Transaction) -> Result<(), ServerError> {
        let status = TimeboostStatusEvent {
            event: TimeboostEventType::Transactions {
                transactions: vec![tx],
            },
        };

        self.app_tx.send(status).await.map_err(|e| ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("Failed to broadcast status event: {}", e),
        })?;

        Ok(())
    }
}

fn define_api<ApiVer: StaticVersionType + 'static>(
) -> Result<Api<RwLock<TimeboostApiState>, ServerError, ApiVer>> {
    let toml = toml::from_str::<toml::Value>(include_str!("../../api/endpoints.toml"))?;
    let mut api = Api::<RwLock<TimeboostApiState>, ServerError, ApiVer>::new(toml)?;

    api.at("post_submit", |req, state| {
        async move {
            let tx = req.body_auto::<Transaction, ApiVer>(ApiVer::instance())?;

            let hash = tx.commit();

            state.write().await.submit(tx).await?;

            Ok(hash)
        }
        .boxed()
    })?;

    api.at("get_metrics", |_req, _state| {
        async move { Ok("fuckoff") }.boxed()
    })?;

    Ok(api)
}
