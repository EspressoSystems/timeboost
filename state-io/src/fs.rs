use std::{io, path::Path};

use tokio::fs;

#[derive(Debug)]
pub struct StateIo(());

impl StateIo {
    pub async fn create() -> io::Result<Self> {
        Ok(Self(()))
    }

    pub async fn load(&mut self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let path = &Path::new(key);
        if !path.is_file() {
            return Ok(None);
        }
        let vec = fs::read(path).await?;
        Ok(Some(vec))
    }

    pub async fn store(&mut self, k: &str, v: &[u8]) -> io::Result<()> {
        let path = &Path::new(k);
        fs::write(path, v).await
    }
}
