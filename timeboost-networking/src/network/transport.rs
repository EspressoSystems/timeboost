use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use futures::future::{select, select_all, Either};
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
use tokio::sync::mpsc::{self, Receiver, Sender, UnboundedReceiver};
use tokio::sync::watch::{self};
use tokio::task::JoinHandle;
use tokio::time::Instant;

const PING_INTERVAL: Duration = Duration::from_secs(10);

// network messages for exchanged by nodes
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

// connection object representing an established connection to a node
pub struct Connection {
    pub remote_id: PeerId,
    pub tx: Sender<NetworkMessage>,
    pub rx: Receiver<NetworkMessage>,
    pub latency: watch::Receiver<Duration>,
}

#[derive(Debug)]
pub struct Transport {
    rx_connection: Receiver<Connection>,
    tx_stop: Option<Sender<()>>,
    server_handle: Option<JoinHandle<()>>,
}

impl Transport {
    pub async fn run(
        local_id: PeerId,
        local_addr: String,
        to_connect: Vec<(PeerId, String)>,
    ) -> Self {
        // parse the string to a socket
        let local_socket = local_addr
            .parse::<std::net::SocketAddr>()
            .expect("Invalid socket address");
        // send tcp streams to the dedicated workers after accepted connection
        let mut worker_senders: HashMap<PeerId, mpsc::UnboundedSender<TcpStream>> =
            HashMap::default();
        // start accepting connections on the local socket
        let server = TcpListener::bind(local_socket)
            .await
            .expect("Unable to bind to socket");

        let handle = Handle::current();
        // when a connection is fully established it will be send on this channel
        let (tx_connection, rx_connection) = mpsc::channel(20);

        // spawn a worker for each node we want a connection to
        for (remote_id, addr) in to_connect.iter() {
            if *remote_id == local_id {
                continue;
            }
            // channel for the TcpStream going from the Server to the Worker
            let (sender, receiver) = mpsc::unbounded_channel();

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

        // channel for stopping the server
        let (tx_stop, rx_stop) = mpsc::channel(1);
        let server_handle = handle.spawn(async {
            Server {
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
        // shutdown the server
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
    server: TcpListener,
    worker_senders: HashMap<PeerId, mpsc::UnboundedSender<TcpStream>>,
}

impl Server {
    async fn run(self, mut stop: Receiver<()>) {
        loop {
            tokio::select! {
                result = self.server.accept() => {
                    tracing::info!("accepting connection");
                    let (mut stream, remote_peer) = result.expect("accept failed");
                    let auth_len = stream.read_u32().await.expect("first 4 bytes is auth size");
                    let auth_len_usize = auth_len as usize;
                    let mut auth = vec![0u8; auth_len_usize];
                    let _ = stream.read_exact(&mut auth).await;
                    let peer_id = PeerId::from_bytes(&auth).expect("handshake starts with an auth token (PeerId)");
                    if let Some(sender) = self.worker_senders.get(&peer_id) {
                        sender.send(stream).ok();
                    } else {
                        tracing::warn!("Dropping connection from unknown peer {remote_peer}");
                    }
                }
                stop = stop.recv() => {
                    if stop.is_none() {
                        tracing::info!("Shutting down network because of closed channel");
                    } else {
                        tracing::info!("Shutting down because of manual intervention");
                    }
                    return;
                }
            }
        }
    }
}

struct Worker {
    local_id: PeerId,
    _local_addr: SocketAddr,
    remote_id: PeerId,
    remote_addr: SocketAddr,
    active: bool,
    tx_connection: Sender<Connection>,
    //    latency_sender: HistogramSender<Duration>,
    //    network_connection_max_latency: Duration,
}

struct WorkerConnection {
    sender: mpsc::Sender<NetworkMessage>,
    receiver: mpsc::Receiver<NetworkMessage>,
    remote_id: PeerId,
    //    latency_sender: HistogramSender<Duration>,
    //latency_last_value_sender: tokio::sync::watch::Sender<Duration>,
}

impl Worker {
    const ACTIVE_HANDSHAKE: u64 = 0xDEADBEEF;
    const PASSIVE_HANDSHAKE: u64 = 0xBEEFDEAD;
    const MAX_SIZE: u32 = 16 * 1024 * 1024;

    async fn run(self, mut receiver: UnboundedReceiver<TcpStream>) -> Option<()> {
        let initial_delay = if self.active {
            Duration::ZERO
        } else {
            sample_delay((Duration::from_secs(1), Duration::from_secs(5)))
        };

        // actively try to establish a connection
        let mut work = self.connect_and_handle(initial_delay).boxed();

        // if a connection has been accepted we will handle it as if it was a passive stream
        // if not, then we try again to establish a handshake
        loop {
            match select(work, receiver.recv().boxed()).await {
                Either::Left((_work, _receiver)) => {
                    let delay = sample_delay((Duration::from_secs(1), Duration::from_secs(5)));
                    work = self.connect_and_handle(delay).boxed();
                }
                Either::Right((received, _work)) => {
                    if let Some(received) = received {
                        tracing::debug!("Replaced connection for {}", self.remote_id);
                        work = self.handle_passive_stream(received).boxed();
                    } else {
                        // Channel closed, server is terminated
                        return None;
                    }
                }
            }
        }
    }

    async fn connect_and_handle(&self, delay: Duration) -> std::io::Result<()> {
        // avoid race between active and passive connections
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
                    println!("sleeping because no connection");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        stream.set_nodelay(true)?;
        self.local_id.to_bytes();
        let auth_token: &[u8] = &self.local_id.to_bytes();

        let token_length: u32 = auth_token.len() as u32;
        stream.write_u32(token_length).await?;
        stream.write_all(auth_token).await?;

        stream.write_u64(Self::ACTIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::PASSIVE_HANDSHAKE {
            tracing::warn!("Invalid passive handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };

        Self::handle_stream(stream, connection).await
    }

    async fn handle_passive_stream(&self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_nodelay(true)?;
        stream.write_u64(Self::PASSIVE_HANDSHAKE).await?;
        let handshake = stream.read_u64().await?;
        if handshake != Self::ACTIVE_HANDSHAKE {
            tracing::warn!("Invalid active handshake: {handshake}");
            return Ok(());
        }
        let Some(connection) = self.make_connection().await else {
            // todo - pass signal to break the main loop
            return Ok(());
        };
        Self::handle_stream(
            stream, connection,
            //, self.network_connection_max_latency
        )
        .await
    }

    async fn handle_stream(stream: TcpStream, connection: WorkerConnection) -> std::io::Result<()> {
        let WorkerConnection {
            sender,
            receiver,
            remote_id,
            //latency_last_value_sender: _,
        } = connection;
        tracing::debug!("Connected to {}", remote_id);
        let (reader, writer) = stream.into_split();
        let (pong_sender, pong_receiver) = mpsc::channel(150);
        let write_fut = Self::handle_write_stream(
            writer,
            receiver,
            pong_receiver,
            //          latency_sender,
            //            latency_last_value_sender,
            //            network_connection_max_latency,
        )
        .boxed();
        let read_fut = Self::handle_read_stream(reader, sender, pong_sender).boxed();
        let (r, _, _) = select_all([write_fut, read_fut]).await;
        tracing::debug!("Disconnected from {}", remote_id);
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
                _deadline = tokio::time::sleep_until(ping_deadline) => {
                    ping_deadline += PING_INTERVAL;
                    let ping_time = start.elapsed().as_micros() as i64;
                    assert!(ping_time > 0);
                    let ping = encode_ping(ping_time);
                    writer.write_all(&ping).await?;
                }
                received = pong_receiver.recv() => {
                    // We have an embedded ping-pong protocol for measuring RTT:
                    //
                    // Every PING_INTERVAL node emits a "ping", positive number encoding some local time
                    // On receiving positive ping, node replies with "pong" which is negative number (e.g. "ping".neg())
                    // On receiving negative number we can calculate RTT(by negating it again and getting original ping time)
                    // todo - we trust remote peer here, might want to enforce ping (not critical for safety though)

                    let Some(ping) = received else {return Ok(())}; // todo - pass signal? (pong_sender closed)
                    if ping == 0 {
                        tracing::warn!("Invalid ping: {ping}");
                        return Ok(());
                    }
                    if ping > 0 {
                        match ping.checked_neg() {
                            Some(pong) => {
                                let pong = encode_ping(pong);
                                writer.write_all(&pong).await?;
                            },
                            None => {
                                tracing::warn!("Invalid ping: {ping}");
                                return Ok(());
                            }
                        }
                    } else {
                        match ping.checked_neg().and_then(|n|u64::try_from(n).ok()) {
                            Some(our_ping) => {
                                let time = start.elapsed().as_micros() as u64;
                                match time.checked_sub(our_ping) {
                                    Some(delay) => {
                                        let d = Duration::from_micros(delay);
                                        // TODO: include latency observer
                                        // latency_sender.observe(d);
                                        // latency_last_value_sender.send(d).ok();

                                        if d >= Duration::from_micros(1000) {
                                            tracing::warn!("High latency connection: {:?}. Breaking now connection.", d);
                                            return Ok(());
                                        }
                                    },
                                    None => {
                                        tracing::warn!("Invalid ping: {ping}, greater then current time {time}");
                                        return Ok(());
                                    }
                                }

                            },
                            None => {
                                tracing::warn!("Invalid pong: {ping}");
                                return Ok(());
                            }
                        }
                    }
                }
                received = receiver.recv() => {
                    // todo - pass signal to break main loop
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
                // ping message
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
                    println!("writing pong");
                    permit.unwrap().send(ping);
                }
                continue;
            }
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
                    tracing::warn!("Failed to deserialize: {}", err);
                    return Ok(());
                }
            }
        }
    }

    async fn make_connection(&self) -> Option<WorkerConnection> {
        let (network_in_sender, network_in_receiver) = mpsc::channel(1_000);
        let (network_out_sender, network_out_receiver) = mpsc::channel(1_000);
        let (_latency_last_value_sender, latency_last_value_receiver) =
            tokio::sync::watch::channel(Duration::from_millis(0));
        let connection = Connection {
            remote_id: self.remote_id,
            tx: network_out_sender,
            rx: network_in_receiver,
            latency: latency_last_value_receiver,
        };

        self.tx_connection.send(connection).await.ok()?;
        Some(WorkerConnection {
            sender: network_in_sender,
            receiver: network_out_receiver,
            remote_id: self.remote_id,
            //latency_last_value_sender, // TODO: latency through ping
        })
    }
}

fn sample_delay(range: (Duration, Duration)) -> Duration {
    ThreadRng::default().gen_range(range.0..range.1)
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
