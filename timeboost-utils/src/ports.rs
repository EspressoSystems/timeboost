use std::{io, net::Ipv4Addr};

use minicbor::{Decode, Encode};
use minicbor_io::{AsyncReader, AsyncWriter, Error, Reader, Writer};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

pub const ALLOCATOR_PORT: u16 = 1500;

#[derive(Debug, Encode, Decode)]
pub enum Request {
    #[cbor(n(0))]
    Alloc(#[n(0)] u16),
}

#[derive(Debug, Encode, Decode)]
pub enum Response {
    #[cbor(n(0))]
    Ports(#[n(0)] Vec<u16>),
}

pub async fn alloc_ports(n: u16) -> Result<Vec<u16>, Error> {
    let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ALLOCATOR_PORT)).await?;
    let mut writer = AsyncWriter::new((&mut stream).compat_write());
    writer.write(Request::Alloc(n)).await?;
    let mut reader = AsyncReader::new(stream.compat());
    let Some(Response::Ports(ps)) = reader.read().await? else {
        return Err(Error::Io(io::ErrorKind::ConnectionReset.into()));
    };
    Ok(ps)
}

pub fn alloc_ports_blocking(n: u16) -> Result<Vec<u16>, Error> {
    let mut stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, ALLOCATOR_PORT))?;
    let mut writer = Writer::new(&mut stream);
    writer.write(Request::Alloc(n))?;
    let mut reader = Reader::new(stream);
    let Some(Response::Ports(ps)) = reader.read()? else {
        return Err(Error::Io(io::ErrorKind::ConnectionReset.into()));
    };
    Ok(ps)
}

pub async fn alloc_port() -> Result<u16, Error> {
    Ok(alloc_ports(1).await?[0])
}

pub fn alloc_port_blocking() -> Result<u16, Error> {
    Ok(alloc_ports_blocking(1)?[0])
}
