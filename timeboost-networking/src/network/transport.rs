use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use futures::future::select_all;
use futures::FutureExt;
use libp2p::PeerId;
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, warn};

/// Duration between pings for latency measurements
const PING_INTERVAL: Duration = Duration::from_secs(10);
/// Size of the channel for sennding established connections
const MAX_CONNECTIONS: usize = 30;
/// Size of the channel for ping/pong protocol
const MAX_PING_CHANNEL_SIZE: usize = 150;

// TODO: no need to wrap bytes anymore
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkMessage(Vec<u8>);
impl NetworkMessage {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for NetworkMessage {
    fn from(bytes: Vec<u8>) -> Self {
        NetworkMessage(bytes)
    }
}

/// A connection represents an established connection to another node.
pub struct Connection {
    /// The Id of the connected peer
    pub remote_id: PeerId,
    /// Channel for sending outbound messages
    pub tx: Sender<NetworkMessage>,
    /// Channel for receiving inbound message
    pub rx: Receiver<NetworkMessage>,
    // Periodic latency measurement
    // pub latency: watch::Receiver<Duration>,
}

/// A transport takes connections from the handshake state to the transport
/// state (established) by conducting a handshake protocol.
#[derive(Debug)]
pub struct Transport {
    /// Channel for receiving established connections
    rx_connection: Receiver<Connection>,
    /// Channel for stopping the server
    tx_stop: Option<Sender<()>>,
    /// Server handle
    server_handle: Option<JoinHandle<()>>,
}

impl Transport {
    /// Spawns the server and one worker per remote node in `to_connect`.
    ///
    /// When the server has accepted a connection the resulting stream
    /// is forwarded to the dedicated `Worker`.
    pub async fn run(
        local_id: PeerId,
        local_addr: String,
        to_connect: Vec<(PeerId, String)>,
    ) -> Self {
        let local_socket = local_addr
            .parse::<std::net::SocketAddr>()
            .expect("Invalid socket address");

        // Channels for sending streams to dedicated workers after accepted connection
        let mut worker_senders: HashMap<PeerId, mpsc::Sender<TcpStream>> = HashMap::default();

        let server = TcpListener::bind(local_socket)
            .await
            .expect("Unable to bind to socket");

        let handle = Handle::current();
        let (tx_connection, rx_connection) = mpsc::channel(MAX_CONNECTIONS);

        // Spawn a worker for each node we want a connection to
        for (remote_id, addr) in to_connect.iter() {
            if *remote_id == local_id {
                continue;
            }
            // Channel for the TcpStream going from the Server to the Worker
            let (sender, receiver) = mpsc::channel(MAX_CONNECTIONS);

            let socket = addr
                .parse::<std::net::SocketAddr>()
                .expect("Invalid socket address");
            assert!(
                worker_senders.insert(*remote_id, sender).is_none(),
                "Duplicated address {} in list",
                socket
            );
            handle.spawn(
                Worker {
                    local_id,
                    _local_addr: local_socket,
                    remote_id: *remote_id,
                    remote_addr: socket,
                    active: *remote_id.to_base58() < *local_id.to_base58(),
                    tx_connection: tx_connection.clone(),
                }
                .run(receiver),
            );
        }
        // Channel for stopping the server
        let (tx_stop, rx_stop) = mpsc::channel(1);
        let server_handle = handle.spawn(async move {
            Server {
                local_id,
                server,
                worker_senders,
            }
            .run(rx_stop)
            .await
        });

        Self {
            rx_connection,
            tx_stop: Some(tx_stop),
            server_handle: Some(server_handle),
        }
    }

    pub fn rx_connection(&mut self) -> &mut Receiver<Connection> {
        &mut self.rx_connection
    }

    pub async fn shutdown(mut self) {
        // Shutdown the server
        if let Some(tx_stop) = self.tx_stop.take() {
            tx_stop.send(()).await.ok();
        }
        if let Some(handle) = self.server_handle.take() {
            handle.await.ok();
        }
    }
}

#[derive(Debug)]
struct Server {
    /// Local id of the node
    local_id: PeerId,
    /// Socket for accepting connections
    server: TcpListener,
    /// Channel for fowarding accepted connections
    worker_senders: HashMap<PeerId, mpsc::Sender<TcpStream>>,
}

impl Server {
    #[instrument(level = "trace", skip_all, fields(node = %self.local_id))]
    async fn run(self, mut stop: Receiver<()>) {
        loop {
            tokio::select! {
                result = self.server.accept() => {
                    // TODO: modify handshake with noise protocol
                    // (handshake state -> transport state)
                    let (mut stream, remote_peer) = result.expect("create tcp stream");
                    let auth_len = stream.read_u32().await.expect("first 4 bytes is auth size");
                    let auth_len_usize = auth_len as usize;
                    let mut auth = vec![0u8; auth_len_usize];
                    let _ = stream.read_exact(&mut auth).await;
                    let peer_id = PeerId::from_bytes(&auth).expect("handshake starts with an auth token (PeerId)");
                    // Send the stream to the dedicated worker
                    if let Some(sender) = self.worker_senders.get(&peer_id) {
                        debug!("Accepted connection from peer: {}", peer_id);
                        sender.send(stream).await.ok();
                    } else {
                        warn!("Dropping connection from unknown peer: {remote_peer} with peer_id: {peer_id}");
                    }
                }
                stop = stop.recv() => {
                    if stop.is_none() {
                        info!("Shutting down server");
                    }
                    return;
                }
            }
        }
    }
}

/// A worker is responsible for establishing a single connection
struct Worker {
    /// The local Id
    local_id: PeerId,
    /// The local address for the server
    _local_addr: SocketAddr,
    /// The remote peer for the connection
    remote_id: PeerId,
    /// The remote address
    remote_addr: SocketAddr,
    /// True if we should make outbound connection
    active: bool,
    /// Channel for sending established the connection (post-handshake)
    tx_connection: Sender<Connection>,
}

/// A worker connection only forwards messages
struct WorkerConnection {
    sender: mpsc::Sender<NetworkMessage>,
    receiver: mpsc::Receiver<NetworkMessage>,
    remote_id: PeerId,
}

impl Worker {
    // TODO: Modify handshake with noise protocol upgrade
    const ACTIVE_HANDSHAKE: u64 = 0xDEADBEEF;
    const PASSIVE_HANDSHAKE: u64 = 0xBEEFDEAD;
    const MAX_SIZE: u32 = 16 * 1024 * 1024;

    async fn run(self, mut receiver: Receiver<TcpStream>) -> Option<()> {
        // Avoid live locks (nodes connecting to each other at the same time)
        let max = Duration::from_secs(5);
        let initial_delay = if self.active {
            sample_delay(max)
        } else {
            Duration::ZERO
        };
        // Actively try to establish a connection
        let mut work = self.active_connect(initial_delay).boxed();

        loop {
            tokio::select! {
                // TODO: double check cancel-safety
                _ = &mut work => {
                    let delay = sample_delay(max);
                    work = self.active_connect(delay).boxed();
                }
                received = receiver.recv() => {
                    if let Some(received) = received {
                        debug!("Replaced connection for {}", self.remote_id);
                        work = self.passive_connect(received).boxed();
                    } else {
                        // Channel closed, server is terminated
                        return None;
                    }
                }
            }
        }
    }

    /// Active (outbound) handshake protocol and subsequent handling of streams
    async fn active_connect(&self, delay: Duration) -> std::io::Result<()> {
        // Avoid races between active and passive connections
        tokio::time::sleep(delay).await;

        let mut stream = loop {
            let socket = if self.remote_addr.is_ipv4() {
                TcpSocket::new_v4().unwrap()
            } else {
                TcpSocket::new_v6().unwrap()
            };

            match socket.connect(self.remote_addr).await {
                Ok(stream) => {
                    break stream;
                }
                Err(_err) => {
                    debug!("Sleeping because no connection");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        stream.set_nodelay(true)?;
        // TODO: Modify authentication with noise protocol upgrade
        self.local_id.to_bytes();
        let auth_token: &[u8] = &self.local_id.to_bytes();

        let token_length: u32 = auth_token.len() as u32;
        stream.write_u32(token_length).await?;
        stream.write_all(auth_token).await?;

        stream.write_u64(Self::ACTIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::PASSIVE_HANDSHAKE {
            warn!("Invalid passive handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };

        Self::handle_stream(stream, connection).await
    }

    /// Passive (inbound) handshake protocol and subsequent handling of streams
    async fn passive_connect(&self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_nodelay(true)?;
        stream.write_u64(Self::PASSIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::ACTIVE_HANDSHAKE {
            warn!("Invalid active handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };
        Self::handle_stream(stream, connection).await
    }

    /// Maintains a `Transport` for this connection after successfull handshake
    async fn handle_stream(stream: TcpStream, connection: WorkerConnection) -> std::io::Result<()> {
        let WorkerConnection {
            sender,
            receiver,
            remote_id,
        } = connection;
        debug!("Connected to {}", remote_id);
        let (reader, writer) = stream.into_split();
        let (pong_sender, pong_receiver) = mpsc::channel(MAX_PING_CHANNEL_SIZE);
        let write_fut = Self::handle_write_stream(
            writer,
            receiver,
            pong_receiver,
            // TODO: measure concrete latency using ping
        )
        .boxed();
        let read_fut = Self::handle_read_stream(reader, sender, pong_sender).boxed();
        let (r, _, _) = select_all([write_fut, read_fut]).await;
        debug!("Disconnected from {}", remote_id);
        r
    }

    async fn handle_write_stream(
        mut writer: OwnedWriteHalf,
        mut receiver: mpsc::Receiver<NetworkMessage>,
        mut pong_receiver: mpsc::Receiver<i64>,
    ) -> std::io::Result<()> {
        let start = Instant::now();
        let mut ping_deadline = start + PING_INTERVAL;
        loop {
            tokio::select! {
                // TODO: Measure latency (rtt) through embedded ping-pong protocol
                _deadline = tokio::time::sleep_until(ping_deadline) => {
                    ping_deadline += PING_INTERVAL;
                    let ping_time = start.elapsed().as_micros() as i64;
                    if ping_time > 0 {
                        error!("Invalid ping time {ping_time}");
                    }
                    let ping = encode_ping(ping_time);
                    writer.write_all(&ping).await?;
                }
                received = pong_receiver.recv() => {
                    let Some(ping) = received else {return Ok(())}; // todo - pass signal? (pong_sender closed)
                    if ping == 0 {
                        warn!("Invalid ping: {ping}");
                        return Ok(());
                    }
                    if ping > 0 {
                        match ping.checked_neg() {
                            Some(pong) => {
                                let pong = encode_ping(pong);
                                writer.write_all(&pong).await?;
                            },
                            None => {
                                warn!("Invalid ping: {ping}");
                                return Ok(());
                            }
                        }
                    } else {
                        match ping.checked_neg().and_then(|n|u64::try_from(n).ok()) {
                            Some(our_ping) => {
                                let time = start.elapsed().as_micros() as u64;
                                match time.checked_sub(our_ping) {
                                    Some(delay) => {
                                        let _d = Duration::from_micros(delay);
                                        // TODO: include latency observer
                                    },
                                    None => {
                                        warn!("Invalid ping: {ping}, greater then current time {time}");
                                        return Ok(());
                                    }
                                }

                            },
                            None => {
                                warn!("Invalid pong: {ping}");
                                return Ok(());
                            }
                        }
                    }
                }
                // Write outbound traffic coming in on the channel
                received = receiver.recv() => {
                    // TODO: Pass signal to break main loop
                    // TODO: No need to wrap bytes in `NetworkMessage`
                    let Some(message) = received else {return Ok(())};
                    let serialized = bincode::serialize(&message).expect("Serialization should not fail");
                    writer.write_u32(serialized.len() as u32).await?;
                    writer.write_all(&serialized).await?;
                }
            }
        }
    }

    async fn handle_read_stream(
        mut stream: OwnedReadHalf,
        sender: mpsc::Sender<NetworkMessage>,
        pong_sender: mpsc::Sender<i64>,
    ) -> std::io::Result<()> {
        let mut buf = vec![0u8; Self::MAX_SIZE as usize].into_boxed_slice();
        loop {
            let size = stream.read_u32().await?;
            if size > Self::MAX_SIZE {
                tracing::warn!("Invalid size: {size}");
                return Ok(());
            }
            if size == 0 {
                let buf = &mut buf[..PING_SIZE - 4];
                let read = stream.read_exact(buf).await?;
                assert_eq!(read, buf.len());
                let ping = decode_ping(buf);
                let permit = pong_sender.try_reserve();
                if let Err(err) = permit {
                    match err {
                        TrySendError::Full(_) => {
                            tracing::error!("Pong sender channel is saturated. Will drop.");
                        }
                        TrySendError::Closed(_) => {
                            return Ok(());
                        }
                    }
                } else {
                    permit.unwrap().send(ping);
                }
                continue;
            }

            // Read inbound traffic and send on channel
            let buf = &mut buf[..size as usize];
            let read = stream.read_exact(buf).await?;
            assert_eq!(read, buf.len());
            match bincode::deserialize::<NetworkMessage>(buf) {
                Ok(message) => {
                    if sender.send(message).await.is_err() {
                        // todo - pass signal to break main loop
                        return Ok(());
                    }
                }
                Err(err) => {
                    warn!("Failed to deserialize: {}", err);
                    return Ok(());
                }
            }
        }
    }

    async fn make_connection(&self) -> Option<WorkerConnection> {
        let (network_in_sender, network_in_receiver) = mpsc::channel(1_000);
        let (network_out_sender, network_out_receiver) = mpsc::channel(1_000);
        let connection = Connection {
            remote_id: self.remote_id,
            tx: network_out_sender,
            rx: network_in_receiver,
            // TODO: Ship latency through ping
        };
        // Send the connection downstream
        self.tx_connection.send(connection).await.ok()?;
        Some(WorkerConnection {
            sender: network_in_sender,
            receiver: network_out_receiver,
            remote_id: self.remote_id,
        })
    }
}

fn sample_delay(max: Duration) -> Duration {
    let start = Duration::from_secs(1);
    ThreadRng::default().gen_range(start..max)
}

const PING_SIZE: usize = 12;
fn encode_ping(message: i64) -> [u8; PING_SIZE] {
    let mut m = [0u8; 12];
    m[4..].copy_from_slice(&message.to_le_bytes());
    m
}

fn decode_ping(message: &[u8]) -> i64 {
    let mut m = [0u8; 8];
    m.copy_from_slice(message);
    i64::from_le_bytes(m)
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::Transport;
    use futures::future::join_all;
    use libp2p::PeerId;
    use timeboost_utils::types::logging::init_logging;

    #[tokio::test]
    async fn network_connect_test() {
        init_logging();
        let (networks, addresses) = networks_and_addresses(5usize).await;
        for (mut network, address) in networks.into_iter().zip(addresses.iter()) {
            let mut waiting_peers: HashSet<_> = HashSet::from_iter(addresses.iter().cloned());
            waiting_peers.remove(address);
            while let Some(connection) = network.rx_connection.recv().await {
                let (peer, addr) = addresses
                    .iter()
                    .find(|(pid, _)| *pid == connection.remote_id)
                    .expect("Peer not found");
                eprintln!("{:?} connected to {:?}", address, peer);
                waiting_peers.retain(|(_, a)| a != addr);
                if waiting_peers.is_empty() {
                    break;
                }
            }
        }
    }

    async fn networks_and_addresses(
        num_of_nodes: usize,
    ) -> (Vec<Transport>, Vec<(PeerId, String)>) {
        let addresses: Vec<_> = (0..num_of_nodes)
            .map(|i| (PeerId::random(), format!("127.0.0.1:{}", 5500 + i)))
            .collect();
        let networks = addresses
            .iter()
            .map(|(pid, addr)| Transport::run(*pid, addr.clone(), addresses.clone()));
        let networks = join_all(networks).await;
        (networks, addresses)
    }
}
