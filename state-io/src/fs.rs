use std::{env, io, path::PathBuf};

use tokio::fs;

use crate::env::TIMEBOOST_STAMP;

#[derive(Debug)]
pub struct StateIo {
    path: PathBuf,
}

impl StateIo {
    pub async fn create() -> io::Result<Self> {
        let path = env::var_os(TIMEBOOST_STAMP).ok_or_else(|| {
            let msg = format!("environment variable {TIMEBOOST_STAMP} not found");
            io::Error::new(io::ErrorKind::NotFound, msg)
        })?;
        Ok(Self { path: path.into() })
    }

    pub async fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.path.is_file() {
            return Ok(None);
        }
        let vec = fs::read(&self.path).await?;
        Ok(Some(vec))
    }

    pub async fn store(&mut self, v: &[u8]) -> io::Result<()> {
        fs::write(&self.path, v).await
    }
}
