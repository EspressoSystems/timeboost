// Copyright (c) 2021-2024 Espresso Systems (espressosys.com)
// This file is part of the HotShot repository.

// You should have received a copy of the MIT License
// along with the HotShot repository. If not, see <https://mit-license.org/>.

/// networking behaviours wrapping libp2p's behaviours
pub mod behaviours;
/// defines the swarm and network definition (internal)
mod def;
/// functionality of a libp2p network node
mod node;
/// Alternative Libp2p transport implementations
pub mod transport;

/// The client side of the network
pub mod client;

use std::{collections::HashSet, fmt::Debug};

use futures::channel::oneshot::Sender;
use hotshot_types::traits::signature_key::SignatureKey;
use libp2p::dns::tokio::Transport as DnsTransport;
use libp2p::{
    build_multiaddr,
    core::{muxing::StreamMuxerBox, transport::Boxed},
    gossipsub::Event as GossipEvent,
    identify::Event as IdentifyEvent,
    identity::Keypair,
    quic,
    request_response::ResponseChannel,
    Multiaddr, Transport,
};
use libp2p_identity::PeerId;
use quic::tokio::Transport as QuicTransport;
use tracing::instrument;
use transport::StakeTableAuthentication;

use crate::NetworkError;

pub use self::{
    def::NetworkDef,
    node::{
        spawn_network_node, GossipConfig, NetworkNode, NetworkNodeConfig, NetworkNodeConfigBuilder,
        NetworkNodeConfigBuilderError, NetworkNodeHandle, NetworkNodeReceiver,
        DEFAULT_REPLICATION_FACTOR,
    },
};

/// Actions to send from the client to the swarm
#[derive(Debug)]
pub enum ClientRequest {
    /// Start the bootstrap process to kademlia
    BeginBootstrap,
    /// kill the swarm
    Shutdown,
    /// broadcast a serialized message
    GossipMsg(String, Vec<u8>),
    /// subscribe to a topic
    Subscribe(String, Option<Sender<()>>),
    /// unsubscribe from a topic
    Unsubscribe(String, Option<Sender<()>>),
    /// client request to send a direct serialized message
    DirectRequest {
        /// peer id
        pid: PeerId,
        /// msg contents
        contents: Vec<u8>,
        /// number of retries
        retry_count: u8,
    },
    /// client request to send a direct reply to a message
    DirectResponse(ResponseChannel<Vec<u8>>, Vec<u8>),
    /// prune a peer
    Prune(PeerId),
    /// add vec of known peers or addresses
    AddKnownPeers(Vec<(PeerId, Multiaddr)>),
    /// Ignore peers. Only here for debugging purposes.
    /// Allows us to have nodes that are never pruned
    IgnorePeers(Vec<PeerId>),
    /// Put(Key, Value) into DHT
    /// relay success back on channel
    PutDHT {
        /// Key to publish under
        key: Vec<u8>,
        /// Value to publish under
        value: Vec<u8>,
        /// Channel to notify caller of result of publishing
        notify: Sender<()>,
    },
    /// Get(Key, Chan)
    GetDHT {
        /// Key to search for
        key: Vec<u8>,
        /// Channel to notify caller of value (or failure to find value)
        notify: Sender<Vec<u8>>,
        /// number of retries to make
        retry_count: u8,
    },
    /// Request the number of connected peers
    GetConnectedPeerNum(Sender<usize>),
    /// Request the set of connected peers
    GetConnectedPeers(Sender<HashSet<PeerId>>),
    /// Print the routing  table to stderr, debugging only
    GetRoutingTable(Sender<()>),
    /// Get address of peer
    LookupPeer(PeerId, Sender<()>),
}

/// events generated by the swarm that we wish
/// to relay to the client
#[derive(Debug)]
pub enum NetworkEvent {
    /// Recv-ed a broadcast
    GossipMsg(Vec<u8>),
    /// Recv-ed a direct message from a node
    DirectRequest(Vec<u8>, PeerId, ResponseChannel<Vec<u8>>),
    /// Recv-ed a direct response from a node (that hopefully was initiated by this node)
    DirectResponse(Vec<u8>, PeerId),
    /// Report that kademlia has successfully bootstrapped into the network
    IsBootstrapped,
    /// The number of connected peers has possibly changed
    ConnectedPeersUpdate(usize),
}

#[derive(Debug)]
/// internal representation of the network events
/// only used for event processing before relaying to client
pub enum NetworkEventInternal {
    /// a DHT event
    DHTEvent(libp2p::kad::Event),
    /// a identify event. Is boxed because this event is much larger than the other ones so we want
    /// to store it on the heap.
    IdentifyEvent(Box<IdentifyEvent>),
    /// a gossip  event
    GossipEvent(Box<GossipEvent>),
    /// a direct message event
    DMEvent(libp2p::request_response::Event<Vec<u8>, Vec<u8>>),
    /// a autonat event
    AutonatEvent(libp2p::autonat::Event),
}

/// Bind all interfaces on port `port`
/// NOTE we may want something more general in the fture.
#[must_use]
pub fn gen_multiaddr(port: u16) -> Multiaddr {
    build_multiaddr!(Ip4([0, 0, 0, 0]), Udp(port), QuicV1)
}

/// `BoxedTransport` is a type alias for a boxed tuple containing a `PeerId` and a `StreamMuxerBox`.
///
/// This type is used to represent a transport in the libp2p network framework. The `PeerId` is a unique identifier for each peer in the network, and the `StreamMuxerBox` is a type of multiplexer that can handle multiple substreams over a single connection.
type BoxedTransport = Boxed<(PeerId, StreamMuxerBox)>;

/// Generates an authenticated transport checked against the stake table.
/// If the stake table or authentication message is not provided, the transport will
/// not participate in stake table authentication.
///
/// # Errors
/// If we could not create a DNS transport
#[instrument(skip(identity))]
pub async fn gen_transport<K: SignatureKey + 'static>(
    identity: Keypair,
    stake_table: Option<HashSet<K>>,
    auth_message: Option<Vec<u8>>,
) -> Result<BoxedTransport, NetworkError> {
    // Create the initial `Quic` transport
    let transport = {
        let mut config = quic::Config::new(&identity);
        config.handshake_timeout = std::time::Duration::from_secs(20);
        QuicTransport::new(config)
    };

    // Require authentication against the stake table
    let transport = StakeTableAuthentication::new(transport, stake_table, auth_message);

    // Support DNS resolution
    let transport = { DnsTransport::system(transport) }
        .map_err(|e| NetworkError::ConfigError(format!("failed to build DNS transport: {e}")))?;

    Ok(transport
        .map(|(peer_id, connection), _| (peer_id, StreamMuxerBox::new(connection)))
        .boxed())
}
