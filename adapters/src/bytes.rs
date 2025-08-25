use std::convert::Infallible;

use bytes::{Bytes, BytesMut};
use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};

pub fn encode<C, W>(b: &Bytes, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>>
where
    W: Write,
{
    e.bytes(b)?.ok()
}

pub fn decode<'b, C>(d: &mut Decoder<'b>, _: &mut C) -> Result<Bytes, DecodeError> {
    Ok(Bytes::copy_from_slice(d.bytes()?))
}

/// `BytesWrite` can be used to encode directly into `BytesMut`.
#[derive(Default)]
pub struct BytesWriter(BytesMut);

impl Write for BytesWriter {
    type Error = Infallible;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

impl From<BytesWriter> for BytesMut {
    fn from(value: BytesWriter) -> Self {
        value.0
    }
}
