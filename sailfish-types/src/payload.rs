use crate::{HasTime, RoundNumber};

pub trait DataSource {
    type Data: HasTime;

    fn next(&mut self, r: RoundNumber) -> Self::Data;
}

impl<P: DataSource> DataSource for Box<P> {
    type Data = P::Data;

    fn next(&mut self, r: RoundNumber) -> Self::Data {
        (**self).next(r)
    }
}

impl<T: HasTime + Clone> DataSource for std::iter::Repeat<T> {
    type Data = T;

    fn next(&mut self, _: RoundNumber) -> Self::Data {
        <Self as std::iter::Iterator>::next(self).expect("`Repeat` is never `None`")
    }
}

impl<F, T: HasTime> DataSource for std::iter::RepeatWith<F>
where
    F: FnMut() -> T,
{
    type Data = T;

    fn next(&mut self, _: RoundNumber) -> Self::Data {
        <Self as std::iter::Iterator>::next(self).expect("`Repeat` is never `None`")
    }
}
