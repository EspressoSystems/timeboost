// Copyright (c) 2021-2024 Espresso Systems (espressosys.com)
// This file is part of the HotShot repository.

// You should have received a copy of the MIT License
// along with the HotShot repository. If not, see <https://mit-license.org/>.

//! Library for p2p communication

use bincode::{
    config::{
        FixintEncoding, LittleEndian, RejectTrailing, WithOtherEndian, WithOtherIntEncoding,
        WithOtherLimit, WithOtherTrailing,
    },
    DefaultOptions, Options,
};

/// Network logic
pub mod network;

/// symbols needed to implement a networking instance over libp2p-netorking
pub mod reexport {
    pub use libp2p::{request_response::ResponseChannel, Multiaddr};
    pub use libp2p_identity::PeerId;
}

/// For the wire format, we use bincode with the following options:
///   - No upper size limit
///   - Little endian encoding
///   - Varint encoding
///   - Reject trailing bytes
#[allow(clippy::type_complexity)]
#[must_use]
#[allow(clippy::type_complexity)]
pub fn bincode_opts() -> WithOtherTrailing<
    WithOtherIntEncoding<
        WithOtherEndian<WithOtherLimit<DefaultOptions, bincode::config::Infinite>, LittleEndian>,
        FixintEncoding,
    >,
    RejectTrailing,
> {
    bincode::DefaultOptions::new()
        .with_no_limit()
        .with_little_endian()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}
