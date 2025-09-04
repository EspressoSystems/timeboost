use std::{
    io::{Read, Write},
    net::Ipv4Addr,
};

use anyhow::Result;
use bincode::{Decode, Encode, config::standard};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const ALLOCATOR_PORT: u16 = 1500;

#[derive(Debug, Encode, Decode)]
pub enum Request {
    Alloc(u16),
}

#[derive(Debug, Encode, Decode)]
pub enum Response {
    Ports(Vec<u16>),
}

pub async fn alloc_ports(n: u16) -> Result<Vec<u16>> {
    let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ALLOCATOR_PORT)).await?;
    let mut buf = bincode::encode_to_vec(Request::Alloc(n), standard())?;
    stream
        .write_u32(buf.len().try_into().expect("request fits into u32 bytes"))
        .await?;
    stream.write_all(&buf).await?;
    let len = stream.read_u32().await?;
    buf.clear();
    buf.resize(len as usize, 0);
    stream.read_exact(&mut buf).await?;
    let res = bincode::decode_from_slice(&buf, bincode::config::standard())?.0;
    let Response::Ports(ps) = res;
    Ok(ps)
}

pub fn alloc_ports_blocking(n: u16) -> Result<Vec<u16>> {
    let mut stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ALLOCATOR_PORT))?;
    let mut buf = bincode::encode_to_vec(Request::Alloc(n), standard())?;
    let mut len: [u8; 4] = u32::try_from(buf.len())
        .expect("request fits into u32 bytes")
        .to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&buf)?;
    stream.read_exact(&mut len)?;
    buf.clear();
    buf.resize(u32::from_be_bytes(len) as usize, 0);
    stream.read_exact(&mut buf)?;
    let res = bincode::decode_from_slice(&buf, standard())?.0;
    let Response::Ports(ps) = res;
    Ok(ps)
}

pub async fn alloc_port() -> Result<u16> {
    Ok(alloc_ports(1).await?[0])
}

pub fn alloc_port_blocking() -> Result<u16> {
    Ok(alloc_ports_blocking(1)?[0])
}
