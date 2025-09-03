use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use anyhow::{Context, Result};
use minicbor_io::{AsyncReader, AsyncWriter};
use timeboost_utils::ports::{ALLOCATOR_PORT, Request, Response};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::{
    compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt},
    task::TaskTracker,
};

#[tokio::main]
async fn main() -> Result<()> {
    let tasks = TaskTracker::new();
    let counter = Arc::new(AtomicU16::new(2048));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, ALLOCATOR_PORT))
        .await
        .context("allocator port is in use")?;

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tasks.spawn(alloc(stream, counter.clone()));
    }
}

async fn alloc(mut stream: TcpStream, ctr: Arc<AtomicU16>) -> Result<()> {
    let mut reader = AsyncReader::new((&mut stream).compat());
    let Some(request) = reader.read().await? else {
        return Ok(());
    };
    let mut writer = AsyncWriter::new(stream.compat_write());
    match request {
        Request::Alloc(n) => {
            let mut ports = Vec::new();
            for _ in 0..n {
                loop {
                    let port = ctr.fetch_add(1, Ordering::Relaxed);
                    if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok() {
                        ports.push(port);
                        break;
                    }
                }
            }
            writer.write(Response::Ports(ports)).await?;
        }
    }
    Ok(())
}
