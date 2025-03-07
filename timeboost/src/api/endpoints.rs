use std::io::{self, ErrorKind};

use anyhow::Result;
use async_lock::RwLock;
use async_trait::async_trait;
use committable::Committable;
use futures::FutureExt;
use tide_disco::{error::ServerError, Api, App, StatusCode, Url};
use timeboost_types::Transaction;
use tokio::sync::mpsc::Sender;
use vbs::version::{StaticVersion, StaticVersionType};

pub struct TimeboostApiState {
    app_tx: Sender<Transaction>,
}

#[async_trait]
pub trait TimeboostApi {
    async fn submit(&self, tx: Transaction) -> Result<(), ServerError>;
}

impl TimeboostApiState {
    pub fn new(app_tx: Sender<Transaction>) -> Self {
        Self { app_tx }
    }

    /// Run the timeboost API.
    pub async fn run(self, url: Url) -> io::Result<()> {
        let api = define_api::<StaticVersion<0, 1>>()
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;
        let state = RwLock::new(self);
        let mut app = App::<RwLock<TimeboostApiState>, ServerError>::with_state(state);
        app.register_module("", api)
            .expect("Failed to register timeboost-api");
        app.serve(url, StaticVersion::<0, 1> {}).await
    }
}

#[async_trait]
impl TimeboostApi for TimeboostApiState {
    /// Submit a transaction to timeboost layer.
    async fn submit(&self, tx: Transaction) -> Result<(), ServerError> {
        self.app_tx.send(tx).await.map_err(|e| ServerError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("Failed to broadcast transaction: {}", e),
        })?;

        Ok(())
    }
}

fn define_api<ApiVer: StaticVersionType + 'static>(
) -> Result<Api<RwLock<TimeboostApiState>, ServerError, ApiVer>> {
    let toml = toml::from_str::<toml::Value>(include_str!("../../api/endpoints.toml"))?;
    let mut api = Api::<RwLock<TimeboostApiState>, ServerError, ApiVer>::new(toml)?;

    api.post("submit", |req, state| {
        async move {
            let tx = req.body_auto::<Transaction, ApiVer>(ApiVer::instance())?;

            let hash = tx.commit();

            state.submit(tx).await?;

            Ok(hash)
        }
        .boxed()
    })?;

    api.get("healthz", |_, _| async move { Ok("running") }.boxed())?;

    Ok(api)
}
