use itertools::{IntoChunks, Itertools};
use sea_orm::{ActiveModelTrait, EntityTrait, Iterable};

pub trait EntityChunkedIter: Sized {
    type Item: ActiveModelTrait;

    fn chunked(self) -> IntoChunks<impl Iterator<Item = Self::Item>>;
}

impl<T> EntityChunkedIter for T
where
    T: IntoIterator,
    <T as IntoIterator>::Item: ActiveModelTrait,
{
    type Item = T::Item;

    fn chunked(self) -> IntoChunks<impl Iterator<Item = Self::Item>> {
        chunked(self)
    }
}

pub fn chunked<M, I>(i: I) -> IntoChunks<impl Iterator<Item = I::Item>>
where
    M: ActiveModelTrait,
    I: IntoIterator<Item = M>,
{
    chunked_with(<M::Entity as EntityTrait>::Column::iter().count(), i)
}

pub fn chunked_with<I>(values: usize, i: I) -> IntoChunks<impl Iterator<Item = I::Item>>
where
    I: IntoIterator,
{
    i.into_iter().chunks(u16::MAX as usize / values - 8)
}
