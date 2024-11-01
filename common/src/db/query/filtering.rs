// SeaORM impls

use super::{Columns, Error, IntoColumns, Query};
use sea_orm::{EntityTrait, QueryFilter, QueryOrder, Select, SelectTwo};

/// Pass a Query instance for filtering
pub trait Filtering<T: EntityTrait> {
    fn filtering(self, search: Query) -> Result<Self, Error>
    where
        Self: Sized + QueryFilter + QueryOrder,
    {
        self.filtering_with(search, Columns::from_entity::<T>())
    }

    fn filtering_with<C: IntoColumns>(self, search: Query, context: C) -> Result<Self, Error>
    where
        Self: Sized + QueryFilter + QueryOrder,
    {
        search.query(self, &context.columns())
    }
}

/// SeaORM Select
impl<T: EntityTrait> Filtering<T> for Select<T> {}

/// SeaORM SelectTwo
impl<E, F> Filtering<E> for SelectTwo<E, F>
where
    E: EntityTrait,
    F: EntityTrait,
{
    fn filtering(self, search: Query) -> Result<Self, Error> {
        self.filtering_with(
            search,
            Columns::from_entity::<E>().add_columns(Columns::from_entity::<F>()),
        )
    }
}
