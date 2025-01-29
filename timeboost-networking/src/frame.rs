/// The header of a frame.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       |       |P|             |                               |
// |Version|  Type |a|  Reserved   |        Payload length         |
// |       |       |r|             |                               |
// |       |       |t|             |                               |
// +-------+-------+-+-------------+-------------------------------+
//
// - Version (4 bits)
// - Type (4 bits)
//    - Data (0)
//    - Ping (1)
//    - Pong (2)
// - Partial (1 bit)
// - Reserved (7 bits)
// - Payload length (16 bits)
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Header(u32);

impl Header {
    /// Create a data header with the given payload length.
    pub fn data(len: u16) -> Self {
        Self(len as u32)
    }

    /// Create a ping header with the given payload length.
    pub fn ping(len: u16) -> Self {
        Self(0x1000000 | len as u32)
    }

    /// Create a pong header with the given payload length.
    pub fn pong(len: u16) -> Self {
        Self(0x2000000 | len as u32)
    }

    /// The type of the frame following this header.
    pub fn frame_type(self) -> Result<Type, u8> {
        match (self.0 & 0xF000000) >> 24 {
            0 => Ok(Type::Data),
            1 => Ok(Type::Ping),
            2 => Ok(Type::Pong),
            t => Err(t as u8),
        }
    }

    /// Set the partial flag to indicate that more frames follow.
    pub fn partial(self) -> Self {
        Self(self.0 | 0x800000)
    }

    /// Is this a data frame header?
    pub fn is_data(self) -> bool {
        self.0 & 0xF000000 == 0
    }

    /// Is this a ping frame header?
    pub fn is_ping(self) -> bool {
        self.0 & 0xF000000 == 0x1000000
    }

    /// Is this a pong frame header?
    pub fn is_pong(self) -> bool {
        self.0 & 0xF000000 == 0x2000000
    }

    /// Is this a partial frame?
    pub fn is_partial(self) -> bool {
        self.0 & 0x800000 == 0x800000
    }

    /// Get the payload length.
    pub fn len(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    /// Convert this header into a byte array.
    pub fn to_bytes(self) -> [u8; 4] {
        self.into()
    }
}

/// The type of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Data,
    Ping,
    Pong,
}

impl From<Header> for [u8; 4] {
    fn from(val: Header) -> Self {
        val.0.to_be_bytes()
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = InvalidHeader;

    fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
        let n = <[u8; 4]>::try_from(val).map_err(|_| InvalidHeader("4-byte slice required"))?;
        Ok(Self(u32::from_be_bytes(n)))
    }
}

impl TryFrom<[u8; 4]> for Header {
    type Error = InvalidHeader;

    fn try_from(val: [u8; 4]) -> Result<Self, Self::Error> {
        Ok(Self(u32::from_be_bytes(val)))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid header: {0}")]
pub struct InvalidHeader(&'static str);

#[cfg(test)]
mod tests {
    use super::{Header, Type};
    use quickcheck::quickcheck;

    quickcheck! {
        fn data(len: u16) -> bool {
            let hdr = Header::data(len);
            hdr.is_data() && !hdr.is_partial() && hdr.frame_type() == Ok(Type::Data)
        }

        fn ping(len: u16) -> bool {
            let hdr = Header::ping(len);
            hdr.is_ping() && !hdr.is_partial() && hdr.frame_type() == Ok(Type::Ping)
        }

        fn pong(len: u16) -> bool {
            let hdr = Header::pong(len);
            hdr.is_pong() && !hdr.is_partial() && hdr.frame_type() == Ok(Type::Pong)
        }

        fn partial_data(len: u16) -> bool {
            Header::data(len).partial().is_partial()
        }

        fn partial_ping(len: u16) -> bool {
            Header::ping(len).partial().is_partial()
        }

        fn partial_pong(len: u16) -> bool {
            Header::pong(len).partial().is_partial()
        }

        fn data_len(len: u16) -> bool {
            Header::data(len).len() == len
        }

        fn ping_len(len: u16) -> bool {
            Header::ping(len).len() == len
        }

        fn pong_len(len: u16) -> bool {
            Header::pong(len).len() == len
        }
    }
}
