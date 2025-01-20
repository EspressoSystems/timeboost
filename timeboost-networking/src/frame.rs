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
// - Reserved (8 bits)
// - Payload length (16 bits)

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Header(u32);

impl Header {
    pub fn data(len: u16) -> Self {
        Self(len as u32)
    }

    pub fn ping(len: u16) -> Self {
        Self(0x1000000 | len as u32)
    }

    pub fn pong(len: u16) -> Self {
        Self(0x2000000 | len as u32)
    }

    pub fn partial(self) -> Self {
        Self(self.0 | 0x800000)
    }

    pub fn is_data(self) -> bool {
        self.0 & 0xF000000 == 0
    }

    pub fn is_ping(self) -> bool {
        self.0 & 0xF000000 == 0x1000000
    }

    pub fn is_pong(self) -> bool {
        self.0 & 0xF000000 == 0x2000000
    }

    pub fn is_partial(self) -> bool {
        self.0 & 0x800000 == 0x800000
    }

    pub fn len(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    pub fn to_bytes(self) -> [u8; 4] {
        self.into()
    }
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
    use super::Header;
    use quickcheck::quickcheck;

    quickcheck! {
        fn data(len: u16) -> bool {
            let hdr = Header::data(len);
            hdr.is_data() && !hdr.is_partial()
        }

        fn ping(len: u16) -> bool {
            let hdr = Header::ping(len);
            hdr.is_ping() && !hdr.is_partial()
        }

        fn pong(len: u16) -> bool {
            let hdr = Header::pong(len);
            hdr.is_pong() && !hdr.is_partial()
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
