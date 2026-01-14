use std::io;

#[derive(Debug)]
pub struct StateIo;

impl StateIo {
    pub async fn create() -> io::Result<Self> {
        Ok(Self)
    }

    pub async fn load(&mut self, _: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    pub async fn store(&mut self, _: &str, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
}
