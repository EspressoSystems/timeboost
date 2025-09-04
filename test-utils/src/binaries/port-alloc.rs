use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use anyhow::{Context, Result};
use bincode::config::standard;
use test_utils::ports::{ALLOCATOR_PORT, Request, Response};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::task::TaskTracker;

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
    let len = stream.read_u32().await?;
    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf).await?;
    match bincode::decode_from_slice(&buf, standard())? {
        (Request::Alloc(n), _) => {
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
            buf.clear();
            bincode::encode_into_std_write(Response::Ports(ports), &mut buf, standard())?;
            stream
                .write_u32(buf.len().try_into().expect("response fits into u32 bytes"))
                .await?;
            stream.write_all(&buf).await?;
        }
    }
    Ok(())
}
