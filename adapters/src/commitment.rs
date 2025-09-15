use committable::{Commitment, Committable};
use minicbor::CborLen;
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
    let b: &[u8] = d.as_ref();
    debug_assert_eq!(b.len(), LEN);
    e.bytes(b)?.ok()
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

pub fn cbor_len<D, C>(_: &Commitment<D>, c: &mut C) -> usize
where
    D: Committable,
{
    LEN.cbor_len(c) + LEN
}
