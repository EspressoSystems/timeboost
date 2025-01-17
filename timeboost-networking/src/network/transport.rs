use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_lock::Mutex;
use bimap::BiBTreeMap;
use futures::future::select_all;
use futures::FutureExt;
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
    pub remote_pk: PublicKey,
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
        local_addr: String,
        bootstrap_nodes: HashMap<PublicKey, String>,
        kp: &Keypair,
    ) -> Self {
        let local_socket = local_addr
            .parse::<std::net::SocketAddr>()
            .expect("invalid socket address");

        // Channels for sending streams to dedicated workers after accepted connection
        let mut worker_senders = HashMap::new();
        let key_map: BiBTreeMap<_, _> = bootstrap_nodes
            .keys()
            .map(|pk| {
                let curve = x25519::PublicKey::try_from(*pk).expect("public key to be derived");
                (*pk, curve)
            })
            .collect();

        let server = TcpListener::bind(local_socket)
            .await
            .expect("unable to bind to socket");
        let (tx_connection, rx_connection) = mpsc::channel(CONNECTION_BUFFER_SIZE);

        // Spawn a worker for each node we want a connection to
        for (remote_pk, addr) in bootstrap_nodes.into_iter() {
            if remote_pk == kp.public_key() {
                continue;
            }
            // Channel for the TcpStream going from the Server to the Worker
            let (sender, receiver) = mpsc::channel(CONNECTION_BUFFER_SIZE);

            let socket = addr
                .parse::<std::net::SocketAddr>()
                .expect("invalid socket address");
            assert!(
                worker_senders.insert(remote_pk, sender).is_none(),
                "duplicated peer {} in list",
                remote_pk
            );
            spawn(
                Worker {
                    remote_addr: socket,
                    active: remote_pk.as_bytes() < kp.public_key().as_bytes(),
                    tx_connection: tx_connection.clone(),
                    keypair: kp.clone(),
                    remote_pk,
                }
                .run(receiver),
            );
        }
        // Channel for stopping the server
        let (tx_stop, rx_stop) = mpsc::channel(1);
        let keypair = kp.clone();
        let server_handle = spawn(async move {
            Server {
                server,
                worker_senders,
                keypair,
                key_map,
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
    /// Socket for accepting connections
    server: TcpListener,
    /// Channel for fowarding accepted connections
    worker_senders: HashMap<PublicKey, mpsc::Sender<(TcpStream, TransportState)>>,
    /// Bidirectional mapping for ed25519 and x25519 public keys
    key_map: BiBTreeMap<PublicKey, x25519::PublicKey>,
    /// The public and private key of this node.
    keypair: Keypair,
}

impl Server {
    #[instrument(level = "trace", skip_all, fields(node = %self.keypair.public_key()))]
    async fn run(self, mut stop: Receiver<()>) {
        loop {
            tokio::select! {
                connection = self.server.accept() => {
                    let Ok((mut stream, _)) = connection else {
                        warn!("failed to accept connection!");
                        continue;
                    };
                    let (state, remote_pk) = match Self::noise_server_handshake(&mut stream, &self.keypair, &self.key_map).await {
                        Ok(val) => val,
                        Err(e) => {
                            let _ = stream.shutdown().await;
                            drop(stream);
                            warn!("error during noise handshake: {}", e);
                            continue;
                        }
                    };
                    // Send the stream to the dedicated worker
                    if let Some(sender) = self.worker_senders.get(&remote_pk) {
                        debug!("accepted connection from bootstrap node: {}", remote_pk);
                        sender.send((stream, state)).await.ok();
                    }
                    // TODO: For now we dont accept connections from non-bootstrap nodes
                    // but we should authenticate and check that the nodes are staked correctly
                }
                stop = stop.recv() => {
                    if stop.is_none() {
                        info!("shutting down server");
                    }
                    return;
                }
            }
        }
    }

    /// Server side of the noise protocol handshake
    /// Create the state machine `HandshakeState`, from the noise parameters then wait for client to start
    /// After we complete the handshake, we try to go into our `TransportState`.
    /// This contains the cyphers for encryption and decryption between client and server.
    /// # Arguments
    ///
    /// * `stream` - A tcp connection to a client who we will try authenticate with
    /// * `key_map` - Bidirectional mapping for ed25519 and x25519 public keys
    ///
    /// # Panics
    ///
    /// Panics if we cant parse the NOISE_PARAMS or our derived ed25519 keypair cannot be mapped to curve25519 (this is needed for the noise protocol)
    async fn noise_server_handshake(
        stream: &mut TcpStream,
        kp: &Keypair,
        key_map: &BiBTreeMap<PublicKey, x25519::PublicKey>,
    ) -> Result<(TransportState, PublicKey), NetworkError> {
        let builder = Builder::new(NOISE_PARAMS.parse().expect("noise parameters to be parsed"));

        // TODO: Add new curve25519 keys instead of converting our ed25519 signing keys
        let sk = x25519::SecretKey::try_from(kp.secret_key()).expect("secret key to be derived");

        let mut handshake = builder
            .local_private_key(&sk.as_bytes()) // first 32 bytes is the secret key
            .build_responder()
            .map_err(|e| {
                NetworkError::ConfigError(format!("failed to initialize noise builder: {}", e))
            })?;

        let m = recv(stream).await?;

        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
        handshake.read_message(&m, &mut buf).map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "failed to read noise message during handshake: {}",
                e
            ))
        })?;

        let len = handshake.write_message(&[], &mut buf).map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "responder failed to write noise message during handshake: {}",
                e
            ))
        })?;
        send(stream, &buf[..len]).await?;

        let state = handshake.into_transport_mode().map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "responder failed to go into transport mode: {}",
                e
            ))
        })?;
        let pk_bytes = state.get_remote_static().expect("static key to be present");
        let pk = x25519::PublicKey::try_from(pk_bytes).map_err(|e| {
            NetworkError::FailedToConvertToPublicKey(format!(
                "could not convert remote static key bytes to x25519: {}",
                e
            ))
        })?;
        let remote_pk = key_map
            .get_by_right(&pk)
            .ok_or_else(|| NetworkError::LookupError("Failed to find ed25519 mapping!".into()))?;
        Ok((state, *remote_pk))
    }
}

/// A worker is responsible for establishing a single connection
struct Worker {
    /// The remote address
    remote_addr: SocketAddr,
    /// True if we should make outbound connection
    active: bool,
    /// Channel for sending established the connection (post-handshake)
    tx_connection: Sender<Connection>,
    /// The public and private key of this node.
    keypair: Keypair,
    /// Public key of node that we are creating a connection to
    remote_pk: PublicKey,
}

/// A worker connection only forwards messages
struct WorkerConnection {
    sender: mpsc::Sender<NetworkMessage>,
    receiver: mpsc::Receiver<NetworkMessage>,
    remote_pk: PublicKey,
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
                    if let Some((stream, state)) = received {
                        debug!("replaced connection for {}", self.remote_pk);
                        work = self.passive_connect(stream, state).boxed();
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
                    debug!("sleeping because no connection");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        stream
            .set_nodelay(true)
            .map_err(|_e| NetworkError::SetNoDelayFailure)?;

        let state =
            match Self::noise_client_handshake(&mut stream, &self.keypair, &self.remote_pk).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = stream.shutdown().await;
                    drop(stream);
                    warn!("error during noise handshake: {}", e);
                    return Err(e);
                }
            };
        let connection = self.make_connection().await?;

        Self::handle_stream(state, stream, connection).await
    }

    /// Client side of the noise protocol handshake
    /// Create the state machine `HandshakeState`, from the noise parameters then start the handshake.
    /// After we complete the handshake, we try to go into our `TransportState`.
    /// This contains the cyphers for encryption and decryption between client and the server.
    /// # Arguments
    ///
    /// * `stream` - A tcp connection to a server who we will try authenticate with
    /// * `kp` - Private and public key of the node
    /// * `remote_pk` - Public key of the remote node we are trying to authentic with
    /// * `local_id - Id of this node
    ///
    /// # Panics
    ///
    /// Panics if we cant parse the NOISE_PARAMS or our derived ed25519 keypair cannot be mapped to curve25519 (this is needed for the noise protocol)
    async fn noise_client_handshake(
        stream: &mut TcpStream,
        kp: &Keypair,
        remote_pk: &PublicKey,
    ) -> Result<TransportState, NetworkError> {
        let builder = Builder::new(NOISE_PARAMS.parse().expect("noise parameters to be parsed"));

        // TODO: Add new curve25519 keys instead of converting our ed25519 signing keys
        let sk = x25519::SecretKey::try_from(kp.secret_key()).expect("secret key to be derived");
        let pk = x25519::PublicKey::try_from(*remote_pk).expect("public key to be derived");

        let mut handshake = builder
            .local_private_key(&sk.as_bytes())
            .remote_public_key(&pk.as_bytes())
            .build_initiator()
            .map_err(|e| {
                NetworkError::ConfigError(format!("failed to initialize noise builder: {}", e))
            })?;
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
        let len = handshake.write_message(&[], &mut buf).map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "initiator failed to write noise message during handshake: {}",
                e
            ))
        })?;
        send(stream, &buf[..len]).await?;

        let m = recv(stream).await?;
        handshake.read_message(&m, &mut buf).map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "initiator failed to read noise message during handshake: {}",
                e
            ))
        })?;

        handshake.into_transport_mode().map_err(|e| {
            NetworkError::FailedToCompleteNoiseHandshake(format!(
                "initiator failed to go into transport mode: {}",
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
            remote_pk,
        } = connection;
        debug!("connected to {}", remote_pk);
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
        debug!("disconnected from {}, reason: {:?}", remote_pk, r);
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
                        warn!("invalid ping time {ping_time}");
                    }
                    let ping = encode_ping(ping_time);
                    writer.write_all(&ping).await.map_err(|e| {
                        NetworkError::MessageSendError(format!("failed to send ping: {}", e))
                    })?;
                }
                received = pong_receiver.recv() => {
                    let Some(ping) = received else {return Ok(())}; // todo - pass signal? (pong_sender closed)
                    if ping == 0 {
                        warn!("invalid ping: {ping}");
                        return Err(
                            NetworkError::MessageReceiveError(format!("invalid ping: {}", ping))
                        );
                    }
                    if ping > 0 {
                        match ping.checked_neg() {
                            Some(pong) => {
                                let pong = encode_ping(pong);
                                writer.write_all(&pong).await.map_err(|e| {
                                    NetworkError::MessageSendError(format!("failed to send pong: {}", e))
                                })?;
                            },
                            None => {
                                warn!("invalid ping: {ping}");
                                return Err(
                                    NetworkError::MessageReceiveError(format!("invalid ping: {}", ping))
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
                                        warn!("invalid ping: {ping}, greater then current time {time}");
                                        return Err(
                                            NetworkError::MessageReceiveError(format!("invalid ping: {ping}, greater then current time {time}"))
                                        );
                                    }
                                }

                            },
                            None => {
                                warn!("invalid pong: {ping}");
                                return Err(NetworkError::MessageReceiveError(format!("invalid pong: {ping}")));
                            }
                        }
                    }
                }
                // Write outbound traffic coming in on the channel
                m = receiver.recv() => {
                    // TODO: Pass signal to break main loop
                    // TODO: No need to wrap bytes in `NetworkMessage`
                    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
                    let msg = m.ok_or_else(|| {
                        NetworkError::ChannelReceiveError("channel has been closed".into())
                    })?;
                    let m = bincode::serialize(&msg).map_err(|e| {
                        NetworkError::FailedToSerialize(format!("failed to serialize message bytes: {}", e))
                    })?;
                    let mut s = state.lock().await;
                    let len = s.write_message(&m, &mut buf).map_err(|e| {
                        NetworkError::MessageSendError(format!("failed to write noise message: {}", e))
                    })?;
                    drop(s);
                    send(&mut writer, &buf[..len]).await?;
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
        let mut buffer = vec![0u8; MAX_NOISE_MESSAGE_SIZE].into_boxed_slice();
        loop {
            let size = stream.read_u16_le().await.map_err(|e| {
                NetworkError::MessageReceiveError(format!("failed to receive message size: {}", e))
            })?;
            if size as usize > MAX_NOISE_MESSAGE_SIZE {
                error!("invalid size: {size}");
                return Err(NetworkError::MessageReceiveError(
                    "message size is greater than supported in noise.".into(),
                ));
            }
            if size == 0 {
                let buf = &mut buffer[..PING_SIZE - LENGTH_SIZE];
                if let Err(err) = stream.read_exact(buf).await {
                    error!("failed to read ping into buffer: {}", err);
                    continue;
                }
                let ping = decode_ping(buf);
                let permit = pong_sender.try_reserve();
                match permit {
                    Err(TrySendError::Full(_)) => {
                        error!("pong sender channel is saturated. Will drop.");
                    }
                    Err(TrySendError::Closed(_)) => {
                        return Err(NetworkError::ChannelReceiveError(
                            "pong channel is closed".into(),
                        ))?;
                    }
                    Ok(permit) => {
                        permit.send(ping);
                    }
                }
                continue;
            }

            // Read inbound traffic and send on channel
            let buf = &mut buffer[..size as usize];
            if let Err(err) = stream.read_exact(buf).await {
                error!("failed to read message into buffer: {}", err);
                continue;
            }
            let mut s = state.lock().await;
            let mut b = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
            let Ok(len) = s.read_message(buf, &mut b) else {
                drop(s);
                warn!("noise failed to read message");
                continue;
            };
            drop(s);
            match bincode::deserialize::<NetworkMessage>(&b[..len]) {
                Ok(message) => {
                    sender.send(message).await.map_err(|e| {
                        NetworkError::ChannelSendError(format!("error sending on channel: {}", e))
                    })?;
                }
                Err(err) => {
                    warn!("failed to deserialize: {}", err);
                    return Err(NetworkError::FailedToDeserialize(err.to_string()));
                }
            }
        }
    }

    async fn make_connection(&self) -> Result<WorkerConnection, NetworkError> {
        let (network_in_sender, network_in_receiver) = mpsc::channel(NETWORK_BUFFER_SIZE);
        let (network_out_sender, network_out_receiver) = mpsc::channel(NETWORK_BUFFER_SIZE);
        let connection = Connection {
            remote_pk: self.remote_pk,
            tx: network_out_sender,
            rx: network_in_receiver,
            // TODO: Ship latency through ping
        };
        // Send the connection downstream
        self.tx_connection.send(connection).await.map_err(|e| {
            NetworkError::ChannelSendError(format!("failed to send connection downstream: {}", e))
        })?;
        Ok(WorkerConnection {
            sender: network_in_sender,
            receiver: network_out_receiver,
            remote_pk: self.remote_pk,
        })
    }
}

fn sample_delay(max: Duration) -> Duration {
    let start = Duration::ZERO;
    ThreadRng::default().gen_range(start..max)
}

fn encode_ping(message: i64) -> [u8; PING_SIZE] {
    let mut m = [0u8; PING_SIZE];
    // first 2 represents the size == 0
    m[LENGTH_SIZE..].copy_from_slice(&message.to_le_bytes());
    m
}

fn decode_ping(message: &[u8]) -> i64 {
    // already consumed the length of the ping message
    let mut m = [0u8; PING_SIZE - LENGTH_SIZE];
    m.copy_from_slice(message);
    i64::from_le_bytes(m)
}

async fn recv(stream: &mut TcpStream) -> Result<Vec<u8>, NetworkError> {
    let len = stream.read_u16_le().await.map_err(|e| {
        NetworkError::MessageReceiveError(format!("failed to receive the message size: {}", e))
    })?;
    let msg_len = usize::from(len);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..]).await.map_err(|e| {
        NetworkError::MessageReceiveError(format!("failed receiving message: {}", e))
    })?;
    Ok(msg)
}

async fn send<W>(writer: &mut W, buf: &[u8]) -> Result<(), NetworkError>
where
    W: AsyncWriteExt + Unpin,
{
    let len = u16::try_from(buf.len()).map_err(|e| {
        NetworkError::MessageSendError(format!(
            "message size is too large for noise protocol: {}",
            e
        ))
    })?;
    writer.write_u16_le(len).await.map_err(|e| {
        NetworkError::MessageSendError(format!("failed to send the message size: {}", e))
    })?;
    writer
        .write_all(buf)
        .await
        .map_err(|e| NetworkError::MessageSendError(format!("failed to send payload: {}", e)))?;
    Ok(())
}
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::Transport;
    use futures::future::join_all;
    use multisig::PublicKey;
    use timeboost_utils::unsafe_zero_keypair;

    #[tokio::test]
    async fn network_connect_test() {
        let (networks, addresses) = networks_and_addresses(5usize).await;
        for (mut network, address) in networks.into_iter().zip(addresses.iter()) {
            let mut waiting_peers = addresses.clone();
            waiting_peers.remove(address.0);
            while let Some(connection) = network.rx_connection.recv().await {
                waiting_peers.remove(&connection.remote_pk);
                if waiting_peers.is_empty() {
                    break;
                }
            }
        }
    }

    async fn networks_and_addresses(
        num_of_nodes: usize,
    ) -> (Vec<Transport>, HashMap<PublicKey, String>) {
        let mut kps = HashMap::new();
        let addresses: HashMap<PublicKey, String> = (0..num_of_nodes)
            .map(|i| {
                let keypair = unsafe_zero_keypair(i as u64);
                kps.insert(keypair.public_key(), keypair.clone());
                (keypair.public_key(), format!("127.0.0.1:{}", 5500 + i))
            })
            .collect();
        let networks = addresses.iter().map(|(pk, addr)| {
            let kp = kps.get(pk).unwrap();
            Transport::run(addr.clone(), addresses.clone(), kp)
        });
        let networks = join_all(networks).await;
        (networks, addresses)
    }
}
