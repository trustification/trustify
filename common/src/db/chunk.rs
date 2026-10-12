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

/// Chunk up the iterator into batches suitable for ingesting into the database.
///
/// The idea is to create batches, which fit into the maximum number of parameters for an SQL
/// statement, when doing `insert_many`. Currently, the limit is `u16::MAX`, which is the limit
/// for PostgreSQL.
///
/// It works like this: `values` is the number of values that will be inserted per item. So the
/// batch size is `u16::MAX / values`. As there may be additional parameters, aside from the ones
/// used for inserting values, we lower the PostgreSQL limit by 128.
///
/// Also, if the number of values per entry exceeds the total maximum, we create batches of 1. This
/// will lead to an error when executing the statement (too many parameters), but that's just the
/// way it is anyway, chunking or not.
pub fn chunked_with<I>(values: usize, i: I) -> IntoChunks<impl Iterator<Item = I::Item>>
where
    I: IntoIterator,
{
    i.into_iter()
        .chunks(((u16::MAX - 128) as usize / values).max(1))
}

/// A lazy iterator of owned batches, retaining no shared grouping state across awaits.
///
/// Only the input iterator and batch size are retained between calls to `next`.
/// Its Send capability follows the input iterator; no cloning or static lifetime is required.
pub struct OwnedBatches<I> {
    iter: I,
    batch_size: usize,
}

impl<I: Iterator> Iterator for OwnedBatches<I> {
    type Item = Vec<I::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        let batch = self.iter.by_ref().take(self.batch_size).collect::<Vec<_>>();
        if batch.is_empty() { None } else { Some(batch) }
    }
}

/// Lazily batch active models using their entity's column count as the bind budget.
///
/// Each batch owns its items and can be moved into an insert before awaiting it.
/// Input order, duplicates and the existing minimum-one policy are preserved.
pub fn owned_chunked<M, I>(items: I) -> OwnedBatches<I::IntoIter>
where
    M: ActiveModelTrait,
    I: IntoIterator<Item = M>,
{
    owned_chunked_with(<M::Entity as EntityTrait>::Column::iter().count(), items)
}

/// Lazily produce owned batches within the same bind budget as [`chunked_with`].
///
/// `values` is the nonzero number of bound columns per item. As in the existing
/// helper, 128 parameters are reserved and at least one item is yielded per batch,
/// even when that item alone exceeds the budget. Zero-column input is not supported.
/// Only one batch is consumed per call to `next`, without reading ahead.
pub fn owned_chunked_with<I>(values: usize, items: I) -> OwnedBatches<I::IntoIter>
where
    I: IntoIterator,
{
    OwnedBatches {
        iter: items.into_iter(),
        batch_size: ((u16::MAX - 128) as usize / values).max(1),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    const BIND_BUDGET: usize = (u16::MAX - 128) as usize;

    fn assert_send<T: Send>(value: T) -> T {
        value
    }

    #[test]
    fn owned_chunk_empty() {
        assert_eq!(owned_chunked_with(1, Vec::<u8>::new()).next(), None);
    }

    #[test]
    fn owned_chunk_exact_partial_multiple_order_and_duplicates() {
        // Three items per statement; the duplicate must not be discarded.
        let values = BIND_BUDGET / 3;
        for (input, expected) in [
            (vec![1, 2, 2], vec![vec![1, 2, 2]]),
            (vec![1, 2], vec![vec![1, 2]]),
            (
                vec![1, 2, 2, 3, 4, 5, 6],
                vec![vec![1, 2, 2], vec![3, 4, 5], vec![6]],
            ),
        ] {
            assert_eq!(
                owned_chunked_with(values, input).collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn owned_chunk_bind_sizing_and_minimum_one() {
        for values in [1, 3, 17, BIND_BUDGET, BIND_BUDGET + 1] {
            let size = (BIND_BUDGET / values).max(1);
            let batches = owned_chunked_with(values, 0..size + 1).collect::<Vec<_>>();
            assert_eq!(batches[0].len(), size);
            assert_eq!(batches[1], vec![size]);
        }
    }

    #[test]
    fn owned_chunk_bounded_lazy_consumption() {
        // A non-Send input is valid: no new global bound is imposed by the helper.
        let consumed = Rc::new(Cell::new(0));
        {
            let input = (0..10).inspect(|_| consumed.set(consumed.get() + 1));
            let mut batches = owned_chunked_with(BIND_BUDGET / 3, input);
            assert_eq!(consumed.get(), 0);
            assert_eq!(batches.next(), Some(vec![0, 1, 2]));
            assert_eq!(consumed.get(), 3);
            assert_eq!(batches.next(), Some(vec![3, 4, 5]));
            assert_eq!(consumed.get(), 6);
        }
        // Leaving the iterator's scope does not consume any remaining items.
        assert_eq!(consumed.get(), 6);
    }

    mod entity {
        use sea_orm::entity::prelude::*;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "batch_test")]
        pub struct Model {
            #[sea_orm(primary_key)]
            pub id: i32,
            pub value: String,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    #[test]
    fn owned_chunk_entity_column_budget() {
        let columns = entity::Column::iter().count();
        let size = BIND_BUDGET / columns;
        let models = (0..size + 1).map(|_| entity::ActiveModel {
            ..Default::default()
        });
        let batches = owned_chunked(models).collect::<Vec<_>>();
        assert_eq!(batches[0].len(), size);
        assert_eq!(batches[1].len(), 1);
    }

    #[tokio::test]
    async fn owned_chunk_borrowed_non_clone_items_across_await() {
        struct Item(String);
        let items = [Item("first".into()), Item("second".into())];
        let batches = owned_chunked_with(BIND_BUDGET, &items);
        assert_send(async {
            let mut names = Vec::new();
            for batch in batches {
                tokio::task::yield_now().await;
                names.extend(batch.into_iter().map(|item| item.0.as_str()));
            }
            assert_eq!(names, ["first", "second"]);
        })
        .await;
    }

    #[test]
    fn owned_chunk_iterator_and_awaiting_future_are_send() {
        let batches = assert_send(owned_chunked_with(BIND_BUDGET / 3, vec![1, 2, 3, 4]));
        let _future = assert_send(async move {
            for batch in batches {
                tokio::task::yield_now().await;
                assert!(!batch.is_empty());
            }
        });
    }
}
