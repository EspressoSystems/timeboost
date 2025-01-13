use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_lock::Mutex;
use futures::future::select_all;
use futures::FutureExt;
use libp2p_identity::PeerId;
use multisig::{x25519, Keypair, PublicKey};
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use snow::{Builder, TransportState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::spawn;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, instrument, warn};

use crate::NetworkError;

type WorkerSender = Arc<Mutex<HashMap<PeerId, mpsc::Sender<(TcpStream, TransportState)>>>>;

/// Duration between pings for latency measurements
const PING_INTERVAL: Duration = Duration::from_secs(10);
/// Size of the channel for sennding established connections
const CONNECTION_BUFFER_SIZE: usize = 30;
/// Size of the channel for ping/pong protocol
const PING_BUFFER_SIZE: usize = 150;
/// Size of the ping protocol message
const PING_SIZE: usize = 10;
/// Length representation (u16) size
const LENGTH_SIZE: usize = 2;
/// Maximum channel size for inbound/outbound messages
const NETWORK_BUFFER_SIZE: usize = 1_000;
/// Max message size using noise protocol
const MAX_NOISE_MESSAGE_SIZE: usize = 1024 * 64;
/// Noise parameters to initialize the builders
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

// TODO: no need to wrap bytes anymore
#[derive(Clone, Debug, Serialize, Deserialize)]
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
        bootstrap_nodes: HashMap<PublicKey, (PeerId, String)>,
        keypair: Keypair,
    ) -> Self {
        let local_socket = local_addr
            .parse::<std::net::SocketAddr>()
            .expect("Invalid socket address");

        // Channels for sending streams to dedicated workers after accepted connection
        let worker_senders: WorkerSender = Arc::new(Mutex::new(HashMap::default()));

        let server = TcpListener::bind(local_socket)
            .await
            .expect("Unable to bind to socket");
        let (tx_connection, rx_connection) = mpsc::channel(CONNECTION_BUFFER_SIZE);

        // Spawn a worker for each node we want a connection to
        for (remote_pk, (remote_id, addr)) in bootstrap_nodes.into_iter() {
            if remote_id == local_id {
                continue;
            }
            // Channel for the TcpStream going from the Server to the Worker
            let (sender, receiver) = mpsc::channel(CONNECTION_BUFFER_SIZE);

            let socket = addr
                .parse::<std::net::SocketAddr>()
                .expect("Invalid socket address");
            assert!(
                worker_senders
                    .lock()
                    .await
                    .insert(remote_id, sender)
                    .is_none(),
                "Duplicated peer {} in list",
                remote_id
            );
            spawn(
                Worker {
                    local_id,
                    _local_addr: local_socket,
                    remote_id,
                    remote_addr: socket,
                    active: remote_id.to_base58() < local_id.to_base58(),
                    tx_connection: tx_connection.clone(),
                    keypair: keypair.clone(),
                    remote_pk,
                }
                .run(receiver),
            );
        }
        // Channel for stopping the server
        let (tx_stop, rx_stop) = mpsc::channel(1);
        let server_handle = spawn(async move {
            Server {
                local_id,
                server,
                worker_senders: Arc::clone(&worker_senders),
                keypair: keypair.clone(),
            }
            .run(rx_stop, tx_connection.clone())
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
    worker_senders: WorkerSender,
    /// The public and private key of this node.
    keypair: Keypair,
}

impl Server {
    #[instrument(level = "trace", skip_all, fields(node = %self.local_id))]
    async fn run(self, mut stop: Receiver<()>, _tx_connection: Sender<Connection>) {
        loop {
            tokio::select! {
                result = self.server.accept() => {
                    let (mut stream, _remote_peer) = result.expect("create tcp stream");
                    // (handshake state -> transport state)
                    let (state, peer_id) = match self.noise_responder_handshake(&mut stream).await {
                        Ok((s, id)) => (s, id),
                        Err(e) => {
                            drop(stream);
                            warn!("Error during noise handshake: {}", e);
                            continue;
                        }
                    };
                    // Send the stream to the dedicated worker
                    if let Some(sender) = self.worker_senders.lock().await.get(&peer_id) {
                        debug!("Accepted connection from bootstrap node: {}", peer_id);
                        sender.send((stream, state)).await.ok();
                    }
                    // TODO: For now we dont accept connections from non-bootstrap nodes
                    // but we should authenticate and check that the nodes are staked correctly
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

    async fn noise_responder_handshake(
        &self,
        stream: &mut TcpStream,
    ) -> Result<(TransportState, PeerId), NetworkError> {
        let builder = Builder::new(NOISE_PARAMS.parse().expect("Noise parameters to be parsed"));

        // TODO: Add new keys instead of doing this conversion
        let sk = x25519::SecretKey::try_from(self.keypair.secret_key())
            .expect("Secret key to be derived");

        let mut handshake = builder
            .local_private_key(&sk.as_bytes()[..32]) // first 32 bytes is the secret key
            .build_responder()
            .expect("Noise builder to be built");
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
        let m = recv(stream).await.map_err(|e| {
            NetworkError::MessageReceiveError(format!(
                "Responder failed receiving handshake message: {}",
                e
            ))
        })?;

        let len = handshake.read_message(&m, &mut buf).map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "Responder failed to read noise message during handshake: {}",
                e
            ))
        })?;
        let peer_id = PeerId::from_bytes(&buf[..len]).expect("peer id");

        let len = handshake.write_message(&[], &mut buf).map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "Responder failed to write noise message during handshake: {}",
                e
            ))
        })?;
        send(stream, &buf[..len]).await.map_err(|e| {
            NetworkError::MessageSendError(format!(
                "Responder failed sending handshake message: {}",
                e
            ))
        })?;

        let state = handshake.into_transport_mode().map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "Responder failed to go into transport mode: {}",
                e
            ))
        })?;
        Ok((state, peer_id))
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
    /// The public and private key of this node.
    keypair: Keypair,
    /// Public key of worker we are creating a connection to
    remote_pk: PublicKey,
}

/// A worker connection only forwards messages
struct WorkerConnection {
    sender: mpsc::Sender<NetworkMessage>,
    receiver: mpsc::Receiver<NetworkMessage>,
    remote_id: PeerId,
}

impl Worker {
    async fn run(self, mut receiver: Receiver<(TcpStream, TransportState)>) -> Option<()> {
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
                        work = self.passive_connect(received.0, received.1).boxed();
                    } else {
                        // Channel closed, server is terminated
                        return None;
                    }
                }
            }
        }
    }

    /// Active (outbound) handshake protocol and subsequent handling of streams
    async fn active_connect(&self, delay: Duration) -> Result<(), NetworkError> {
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
        stream
            .set_nodelay(true)
            .map_err(|_e| NetworkError::SetNoDelayFailure)?;

        let state = match self.noise_initiator_handshake(&mut stream).await {
            Ok(s) => s,
            Err(e) => {
                drop(stream);
                warn!("Error during noise handshake: {}", e);
                return Err(e);
            }
        };
        let connection = self.make_connection().await?;

        Self::handle_stream(state, stream, connection).await
    }

    async fn noise_initiator_handshake(
        &self,
        stream: &mut TcpStream,
    ) -> Result<TransportState, NetworkError> {
        let builder = Builder::new(NOISE_PARAMS.parse().expect("Noise parameters to be parsed"));

        // TODO: Add new keys instead of doing this conversion
        let sk = x25519::SecretKey::try_from(self.keypair.secret_key())
            .expect("Secret key to be derived");
        let pk = x25519::PublicKey::try_from(self.remote_pk).expect("Secret key to be derived");

        let mut handshake = builder
            .local_private_key(&sk.as_bytes()[..32])
            .remote_public_key(&pk.as_bytes())
            .build_initiator()
            .expect("Noise initiator builder to be built");
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
        let len = handshake
            .write_message(&self.local_id.to_bytes(), &mut buf)
            .map_err(|e| {
                NetworkError::FailedToCompleteNoiseHandshake(format!(
                    "Initiator failed to write noise message during handshake: {}",
                    e
                ))
            })?;
        send(stream, &buf[..len]).await.map_err(|e| {
            NetworkError::MessageSendError(format!(
                "Initiator failed to send message during noise handshake: {}",
                e
            ))
        })?;

        handshake
            .read_message(&recv(stream).await.unwrap(), &mut buf)
            .map_err(|e| {
                NetworkError::FailedToCompleteNoiseHandshake(format!(
                    "Initiator failed to write noise message during handshake: {}",
                    e
                ))
            })?;

        handshake.into_transport_mode().map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "Initiator failed to go into transport mode: {}",
                e
            ))
        })
    }

    /// Passive (inbound) handshake protocol and subsequent handling of streams
    async fn passive_connect(
        &self,
        stream: TcpStream,
        state: TransportState,
    ) -> Result<(), NetworkError> {
        stream
            .set_nodelay(true)
            .map_err(|_e| NetworkError::SetNoDelayFailure)?;
        let connection = self.make_connection().await?;
        Self::handle_stream(state, stream, connection).await
    }

    /// Maintains a `Transport` for this connection after successfull handshake
    async fn handle_stream(
        state: TransportState,
        stream: TcpStream,
        connection: WorkerConnection,
    ) -> Result<(), NetworkError> {
        let WorkerConnection {
            sender,
            receiver,
            remote_id,
        } = connection;
        debug!("Connected to {}", remote_id);
        let (reader, writer) = stream.into_split();
        let writer_state = Arc::new(Mutex::new(state));
        let reader_state = Arc::clone(&writer_state);
        let (pong_sender, pong_receiver) = mpsc::channel(PING_BUFFER_SIZE);
        let write_fut = Self::handle_write_stream(
            writer_state,
            writer,
            receiver,
            pong_receiver,
            // TODO: measure concrete latency using ping
        )
        .boxed();
        let read_fut = Self::handle_read_stream(reader_state, reader, sender, pong_sender).boxed();
        let (r, _, _) = select_all([write_fut, read_fut]).await;
        debug!("Disconnected from {}", remote_id);
        r
    }

    async fn handle_write_stream(
        state: Arc<Mutex<TransportState>>,
        mut writer: OwnedWriteHalf,
        mut receiver: mpsc::Receiver<NetworkMessage>,
        mut pong_receiver: mpsc::Receiver<i64>,
    ) -> Result<(), NetworkError> {
        let start = Instant::now();
        let mut ping_deadline = start + PING_INTERVAL;
        loop {
            tokio::select! {
                // TODO: Measure latency (rtt) through embedded ping-pong protocol
                _deadline = tokio::time::sleep_until(ping_deadline) => {
                    ping_deadline += PING_INTERVAL;
                    let ping_time = start.elapsed().as_micros() as i64;
                    if ping_time <= 0 {
                        warn!("Invalid ping time {ping_time}");
                    }
                    let ping = encode_ping(ping_time);
                    writer.write_all(&ping).await.map_err(|e| {
                        NetworkError::MessageSendError(format!("Failed to send ping: {}", e))
                    })?;
                }
                received = pong_receiver.recv() => {
                    let Some(ping) = received else {return Ok(())}; // todo - pass signal? (pong_sender closed)
                    if ping == 0 {
                        warn!("Invalid ping: {ping}");
                        return Err(
                            NetworkError::MessageReceiveError(format!("Invalid ping: {}", ping))
                        );
                    }
                    if ping > 0 {
                        match ping.checked_neg() {
                            Some(pong) => {
                                let pong = encode_ping(pong);
                                writer.write_all(&pong).await.map_err(|e| {
                                    NetworkError::MessageSendError(format!("Failed to send pong: {}", e))
                                })?;
                            },
                            None => {
                                warn!("Invalid ping: {ping}");
                                return Err(
                                    NetworkError::MessageReceiveError(format!("Invalid ping: {}", ping))
                                );
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
                                        return Err(
                                            NetworkError::MessageReceiveError(format!("Invalid ping: {ping}, greater then current time {time}"))
                                        );
                                    }
                                }

                            },
                            None => {
                                warn!("Invalid pong: {ping}");
                                return Err(NetworkError::MessageReceiveError(format!("Invalid pong: {ping}")));
                            }
                        }
                    }
                }
                // Write outbound traffic coming in on the channel
                received = receiver.recv() => {
                    // TODO: Pass signal to break main loop
                    // TODO: No need to wrap bytes in `NetworkMessage`
                    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
                    let message = received.ok_or_else(|| {
                        NetworkError::ChannelReceiveError("Message received on channel was None".into())
                    })?;
                    let m = bincode::serialize(&message).expect("Serialization should not fail");
                    let mut s = state.lock().await;
                    let len = s.write_message(&m, &mut buf).unwrap();
                    drop(s);
                    writer.write_u16_le(u16::try_from(len).expect("Message too large")).await.map_err(|e| {
                        NetworkError::MessageSendError(format!("Failed to send message size: {}", e))
                    })?;
                    writer.write_all(&buf[..len]).await.map_err(|e| {
                        NetworkError::MessageSendError(format!("Failed to send payload: {}", e))
                    })?;
                }
            }
        }
    }

    async fn handle_read_stream(
        state: Arc<Mutex<TransportState>>,
        mut stream: OwnedReadHalf,
        sender: mpsc::Sender<NetworkMessage>,
        pong_sender: mpsc::Sender<i64>,
    ) -> Result<(), NetworkError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE].into_boxed_slice();
        loop {
            let size = stream.read_u16_le().await.map_err(|e| {
                NetworkError::MessageReceiveError(format!("Failed to receive message size: {}", e))
            })?;
            if size as usize > MAX_NOISE_MESSAGE_SIZE {
                error!("Invalid size: {size}");
                return Err(NetworkError::MessageReceiveError(
                    "Message size is greater than supported in noise.".into(),
                ));
            }
            if size == 0 {
                let buf = &mut buf[..PING_SIZE - LENGTH_SIZE];
                if let Err(err) = stream.read_exact(buf).await {
                    error!("Failed to read ping into buffer: {}", err);
                    continue;
                }
                let ping = decode_ping(buf);
                let permit = pong_sender.try_reserve();
                match permit {
                    Err(TrySendError::Full(_)) => {
                        error!("Pong sender channel is saturated. Will drop.");
                    }
                    Err(TrySendError::Closed(_)) => {
                        return Err(NetworkError::ChannelReceiveError(
                            "Pong channel is closed".into(),
                        ))?;
                    }
                    Ok(permit) => {
                        permit.send(ping);
                    }
                }
                continue;
            }

            // Read inbound traffic and send on channel
            let buf = &mut buf[..size as usize];
            if let Err(err) = stream.read_exact(buf).await {
                error!("Failed to read message into buffer: {}", err);
                continue;
            }
            let mut s = state.lock().await;
            let mut m = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
            let Ok(len) = s.read_message(buf, &mut m) else {
                drop(s);
                warn!("Noise failed to read message");
                continue;
            };
            drop(s);
            match bincode::deserialize::<NetworkMessage>(&m[..len]) {
                Ok(message) => {
                    sender.send(message).await.map_err(|e| {
                        NetworkError::ChannelSendError(format!("Error sending on channel: {}", e))
                    })?;
                }
                Err(err) => {
                    warn!("Failed to deserialize: {}", err);
                    return Err(NetworkError::FailedToDeserialize(err.to_string()));
                }
            }
        }
    }

    async fn make_connection(&self) -> Result<WorkerConnection, NetworkError> {
        let (network_in_sender, network_in_receiver) = mpsc::channel(NETWORK_BUFFER_SIZE);
        let (network_out_sender, network_out_receiver) = mpsc::channel(NETWORK_BUFFER_SIZE);
        let connection = Connection {
            remote_id: self.remote_id,
            tx: network_out_sender,
            rx: network_in_receiver,
            // TODO: Ship latency through ping
        };
        // Send the connection downstream
        self.tx_connection.send(connection).await.map_err(|e| {
            NetworkError::ChannelSendError(format!("Failed to send connection downstream: {}", e))
        })?;
        Ok(WorkerConnection {
            sender: network_in_sender,
            receiver: network_out_receiver,
            remote_id: self.remote_id,
        })
    }
}

fn sample_delay(max: Duration) -> Duration {
    let start = Duration::ZERO;
    ThreadRng::default().gen_range(start..max)
}

fn encode_ping(message: i64) -> [u8; PING_SIZE] {
    let mut m = [0u8; PING_SIZE];
    // first 4 represents the size == 0
    m[LENGTH_SIZE..].copy_from_slice(&message.to_le_bytes());
    m
}

fn decode_ping(message: &[u8]) -> i64 {
    // already consumed the length of the ping message
    let mut m = [0u8; PING_SIZE - LENGTH_SIZE];
    m.copy_from_slice(message);
    i64::from_le_bytes(m)
}

async fn recv(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let msg_len_buf = stream.read_u16_le().await?;
    let msg_len = usize::from(msg_len_buf);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..]).await?;
    Ok(msg)
}

async fn send(stream: &mut TcpStream, buf: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(buf.len()).expect("message too large");
    stream.write_u16_le(len).await?;
    stream.write_all(buf).await?;
    stream.flush().await?;
    Ok(())
}
#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};

    use crate::derive_peer_id;

    use super::Transport;
    use futures::future::join_all;
    use libp2p_identity::PeerId;
    use multisig::PublicKey;
    use timeboost_utils::unsafe_zero_keypair;

    #[tokio::test]
    async fn network_connect_test() {
        let (networks, addresses) = networks_and_addresses(5usize).await;
        for (mut network, address) in networks.into_iter().zip(addresses.iter()) {
            let mut waiting_peers: HashSet<_> = HashSet::from_iter(addresses.iter().cloned());
            waiting_peers.remove(address);
            while let Some(connection) = network.rx_connection.recv().await {
                let (_, addr) = addresses
                    .iter()
                    .find(|(pid, _)| *pid == connection.remote_id)
                    .expect("Peer not found");
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
        let mut kps = HashMap::new();
        let addresses: HashMap<PublicKey, (PeerId, String)> = (0..num_of_nodes)
            .map(|i| {
                let keypair = unsafe_zero_keypair(i as u64);
                kps.insert(keypair.public_key(), keypair.clone());
                let peer_id = derive_peer_id::<PublicKey>(&keypair.secret_key()).unwrap();
                (
                    keypair.public_key(),
                    (peer_id, format!("127.0.0.1:{}", 5500 + i)),
                )
            })
            .collect();
        let networks = addresses.iter().map(|(pk, (pid, addr))| {
            Transport::run(
                *pid,
                addr.clone(),
                addresses.clone(),
                kps.remove(pk).unwrap(),
            )
        });
        let networks = join_all(networks).await;
        (networks, addresses.into_values().collect())
    }
}
