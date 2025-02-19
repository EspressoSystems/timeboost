use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

use data_encoding::BASE64URL_NOPAD;
use serde::{Serialize, Deserialize};

const INVALID_UTF8: [u8; 2] = [0xC0u8, 0x7Fu8];

pub trait Committable {
    /// Create a binding commitment to `self`.
    fn commit(&self) -> Commitment<Self>;
}

impl Committable for () {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("unit").finalize()
    }
}

#[derive(Deserialize, Serialize)]
pub struct Commitment<T: ?Sized>([u8; 32], #[serde(skip)] PhantomData<fn(&T)>);

impl<T: ?Sized> Copy for Commitment<T> {}

impl<T: ?Sized> Clone for Commitment<T> {
    fn clone(&self) -> Self {
        Self(self.0, PhantomData)
    }
}

impl<T: ?Sized> Eq for Commitment<T> {}

impl<T: ?Sized> PartialEq for Commitment<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: ?Sized> Ord for Commitment<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T: ?Sized> PartialOrd for Commitment<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: ?Sized> Hash for Commitment<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<T: ?Sized> AsRef<[u8]> for Commitment<T> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<T: ?Sized> From<Commitment<T>> for [u8; 32] {
    fn from(v: Commitment<T>) -> Self {
        v.0
    }
}

impl<T: ?Sized> From<[u8; 32]> for Commitment<T> {
    fn from(v: [u8; 32]) -> Self {
        Self(v, PhantomData)
    }
}

impl<T: ?Sized> fmt::Debug for Commitment<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<T: ?Sized> fmt::Display for Commitment<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64URL_NOPAD.encode(self.as_ref()))
    }
}

pub struct RawCommitmentBuilder<T> {
    hasher: blake3::Hasher,
    _marker: PhantomData<T>,
}

impl<T: Committable> RawCommitmentBuilder<T> {
    pub fn new(tag: &str) -> Self {
        Self {
            hasher: Default::default(),
            _marker: Default::default(),
        }
        .constant_str(tag)
    }

    pub fn constant_str(mut self, s: &str) -> Self {
        self.hasher.update(s.as_bytes());
        self.fixed_size_bytes(&INVALID_UTF8)
    }

    pub fn fixed_size_bytes<const N: usize>(mut self, f: &[u8; N]) -> Self {
        self.hasher.update(f);
        self
    }

    pub fn optional<N: Committable>(self, field: &str, o: &Option<N>) -> Self {
        match o {
            Some(s) => {
                let commit = s.commit();
                self.fixed_size_field(field, &commit.0)
            }
            None => self.u64_field(field, 0),
        }
    }

    pub fn u64(self, val: u64) -> Self {
        self.fixed_size_bytes(&val.to_le_bytes())
    }

    pub fn u32(self, val: u32) -> Self {
        self.fixed_size_bytes(&val.to_le_bytes())
    }

    pub fn u16(self, val: u16) -> Self {
        self.fixed_size_bytes(&val.to_le_bytes())
    }

    pub fn var_size_bytes(self, f: &[u8]) -> Self {
        let mut ret = self.u64(f.len() as u64);
        ret.hasher.update(f);
        ret
    }

    pub fn fixed_size_field<const N: usize>(self, name: &str, val: &[u8; N]) -> Self {
        self.constant_str(name).fixed_size_bytes(val)
    }

    pub fn var_size_field(self, name: &str, val: &[u8]) -> Self {
        self.constant_str(name).var_size_bytes(val)
    }

    pub fn field<S: Committable>(self, name: &str, val: Commitment<S>) -> Self {
        self.constant_str(name).fixed_size_bytes(&val.0)
    }

    pub fn u64_field(self, name: &str, val: u64) -> Self {
        self.constant_str(name).u64(val)
    }

    pub fn array_field<S: Committable>(self, name: &str, val: &[Commitment<S>]) -> Self {
        let mut ret = self.constant_str(name).u64(val.len() as u64);
        for v in val.iter() {
            ret = ret.fixed_size_bytes(&v.0);
        }
        ret
    }

    pub fn finalize(self) -> Commitment<T> {
        let ret = self.hasher.finalize();
        Commitment(ret.into(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::{Committable, Commitment, RawCommitmentBuilder, INVALID_UTF8};
    use quickcheck_macros::quickcheck;

    struct DummyCommittable;

    impl Committable for DummyCommittable {
        fn commit(&self) -> Commitment<Self> {
            Commitment([0u8; 32], PhantomData)
        }
    }

    #[test]
    fn test_optional() {
        struct DummyStruct {
            f1: Option<DummyCommittable>,
        }

        impl Committable for DummyStruct {
            fn commit(&self) -> Commitment<Self> {
                RawCommitmentBuilder::new("dummy_struct")
                    .optional("f1", &self.f1)
                    .finalize()
            }
        }

        let dummy1 = DummyStruct { f1: None };
        dummy1.commit();

        let dummy2 = DummyStruct {
            f1: Some(DummyCommittable),
        };
        dummy2.commit();
    }

    #[quickcheck]
    fn invalid_utf8_is_invalid(pref: Vec<u8>, suff: Vec<u8>) {
        let s = pref
            .into_iter()
            .chain(INVALID_UTF8.iter().cloned())
            .chain(suff.into_iter())
            .collect::<Vec<_>>();
        assert!(std::str::from_utf8(&s).is_err());
    }

    #[quickcheck]
    fn invalid_utf8_is_invalid_strs_only(pref: String, suff: String) {
        let s = pref
            .as_bytes()
            .iter()
            .chain(INVALID_UTF8.iter())
            .chain(suff.as_bytes().iter())
            .cloned()
            .collect::<Vec<_>>();
        assert!(std::str::from_utf8(&s).is_err());
    }
}
