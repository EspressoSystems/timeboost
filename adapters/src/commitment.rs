use committable::{Commitment, Committable};
use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};

const LEN: usize = 32;

pub fn encode<D, C, W>(
    d: &Commitment<D>,
    e: &mut Encoder<W>,
    _: &mut C,
) -> Result<(), EncodeError<W::Error>>
where
    W: Write,
    D: Committable,
{
    e.bytes(d.as_ref())?.ok()
}

pub fn decode<'b, D, C>(d: &mut Decoder<'b>, _: &mut C) -> Result<Commitment<D>, DecodeError>
where
    D: Committable,
{
    let p = d.position();
    let a = d.bytes()?;
    <[u8; LEN]>::try_from(a)
        .map(Commitment::from_raw)
        .map_err(|e| DecodeError::custom(e).at(p))
}
