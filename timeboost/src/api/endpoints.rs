use std::io;

use anyhow::Result;
use async_lock::RwLock;
use async_trait::async_trait;
use futures::FutureExt;
use tide_disco::{Api, App, StatusCode, Url, error::ServerError};
use timeboost_types::{Bundle, BundleVariant, SignedPriorityBundle};
use tokio::sync::mpsc::Sender;
use vbs::version::{StaticVersion, StaticVersionType};

pub struct TimeboostApiState {
    app_tx: Sender<BundleVariant>,
}

#[async_trait]
pub trait TimeboostApi {
    async fn submit_priority(&self, bundle: SignedPriorityBundle) -> Result<(), ServerError>;
    async fn submit_regular(&self, bundle: Bundle) -> Result<(), ServerError>;
}

impl TimeboostApiState {
    pub fn new(app_tx: Sender<BundleVariant>) -> Self {
        Self { app_tx }
    }

    /// Run the timeboost API.
    pub async fn run(self, url: Url) -> io::Result<()> {
        let api =
            define_api::<StaticVersion<0, 1>>().map_err(|e| io::Error::other(e.to_string()))?;
        let state = RwLock::new(self);
        let mut app = App::<RwLock<TimeboostApiState>, ServerError>::with_state(state);
        app.register_module("", api)
            .expect("Failed to register timeboost-api");
        app.serve(url, StaticVersion::<0, 1> {}).await
    }
}

#[async_trait]
impl TimeboostApi for TimeboostApiState {
    /// Submit priority bundle to timeboost layer.
    async fn submit_priority(&self, bundle: SignedPriorityBundle) -> Result<(), ServerError> {
        self.app_tx
            .send(BundleVariant::Priority(bundle))
            .await
            .map_err(|e| ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: format!("Failed to broadcast transaction: {e}"),
            })?;

        Ok(())
    }
    /// Submit regular (non-priority) bundle to timeboost layer.
    async fn submit_regular(&self, bundle: Bundle) -> Result<(), ServerError> {
        self.app_tx
            .send(BundleVariant::Regular(bundle))
            .await
            .map_err(|e| ServerError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: format!("Failed to broadcast transaction: {e}"),
            })?;

        Ok(())
    }
}

fn define_api<ApiVer: StaticVersionType + 'static>()
-> Result<Api<RwLock<TimeboostApiState>, ServerError, ApiVer>> {
    let toml = toml::from_str::<toml::Value>(include_str!("../../api/endpoints.toml"))?;
    let mut api = Api::<RwLock<TimeboostApiState>, ServerError, ApiVer>::new(toml)?;

    api.post("submit-priority", |req, state| {
        async move {
            let priority_bundle =
                req.body_auto::<SignedPriorityBundle, ApiVer>(ApiVer::instance())?;

            state.submit_priority(priority_bundle).await?;

            Ok(())
        }
        .boxed()
    })?;

    api.post("submit-regular", |req, state| {
        async move {
            let regular_bundle = req.body_auto::<Bundle, ApiVer>(ApiVer::instance())?;

            state.submit_regular(regular_bundle).await?;

            Ok(())
        }
        .boxed()
    })?;

    api.get("healthz", |_, _| async move { Ok("running") }.boxed())?;

    Ok(api)
}
