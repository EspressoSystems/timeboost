use std::future::Future;
use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::Address;

/// A TCP listener type.
pub trait Listener: Sized {
    type Stream: Stream;

    /// Bind to the given socket address.
    fn bind(addr: &Address) -> impl Future<Output = io::Result<Self>> + Send;

    /// Accept an inbound TCP connection.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send;

    /// Return the local listen address.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// TCP stream type.
pub trait Stream: AsyncRead + AsyncWrite + Sized {
    /// Create a new TCP stream by connecting to the given address.
    fn connect(addr: &Address) -> impl Future<Output = io::Result<Self>> + Send;

    /// Set the `TCP_NODELAY` socket option (disables Nagle's algorithm).
    ///
    /// Segments are sent as soon as possible.
    fn set_nodelay(&self, val: bool) -> io::Result<()>;

    /// Return this stream's peer address.
    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// Split this stream into a read and a write half.
    #[rustfmt::skip]
    fn into_split(self) -> (impl AsyncRead + Unpin + Send, impl AsyncWrite + Unpin + Send);
}

impl Listener for tokio::net::TcpListener {
    type Stream = tokio::net::TcpStream;

    async fn bind(addr: &Address) -> io::Result<Self> {
        match addr {
            Address::Inet(a, p) => tokio::net::TcpListener::bind((*a, *p)).await,
            Address::Name(h, p) => tokio::net::TcpListener::bind((&**h, *p)).await,
        }
    }

    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        self.accept().await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}

#[cfg(feature = "turmoil")]
impl Listener for turmoil::net::TcpListener {
    type Stream = turmoil::net::TcpStream;

    async fn bind(addr: &Address) -> io::Result<Self> {
        match addr {
            Address::Inet(a, p) => turmoil::net::TcpListener::bind((*a, *p)).await,
            Address::Name(h, p) => turmoil::net::TcpListener::bind((&**h, *p)).await,
        }
    }

    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        self.accept().await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }
}

impl Stream for tokio::net::TcpStream {
    async fn connect(addr: &Address) -> io::Result<Self> {
        match addr {
            Address::Inet(a, p) => tokio::net::TcpStream::connect((*a, *p)).await,
            Address::Name(h, p) => tokio::net::TcpStream::connect((&**h, *p)).await,
        }
    }

    fn set_nodelay(&self, val: bool) -> io::Result<()> {
        self.set_nodelay(val)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr()
    }

    #[rustfmt::skip]
    fn into_split(self) -> (impl AsyncRead + Unpin + Send, impl AsyncWrite + Unpin + Send) {
        self.into_split()
    }
}

#[cfg(feature = "turmoil")]
impl Stream for turmoil::net::TcpStream {
    async fn connect(addr: &Address) -> io::Result<Self> {
        match addr {
            Address::Inet(a, p) => turmoil::net::TcpStream::connect((*a, *p)).await,
            Address::Name(h, p) => turmoil::net::TcpStream::connect((&**h, *p)).await,
        }
    }

    fn set_nodelay(&self, val: bool) -> io::Result<()> {
        self.set_nodelay(val)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr()
    }

    #[rustfmt::skip]
    fn into_split(self) -> (impl AsyncRead + Unpin + Send, impl AsyncWrite + Unpin + Send) {
        self.into_split()
    }
}
