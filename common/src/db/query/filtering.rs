// SeaORM impls

use super::{Columns, Error, IntoColumns, Query, Sort};
use sea_orm::{EntityTrait, QueryFilter, Select};

/// Pass a Query instance for filtering
pub trait Filtering<T: EntityTrait> {
    fn filtering(self, search: Query) -> Result<Self, Error>
    where
        Self: Sized,
    {
        self.filtering_with(search, Columns::from_entity::<T>())
    }

    fn filtering_with<C: IntoColumns>(self, search: Query, context: C) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Implement filtering for a Select statement
impl<T: EntityTrait> Filtering<T> for Select<T> {
    fn filtering_with<C: IntoColumns>(self, search: Query, context: C) -> Result<Self, Error> {
        let Query { q, sort, .. } = &search;
        log::debug!("filtering with: q='{q}' sort='{sort}'");
        let columns = context.columns();
        // filter the query
        let result = if q.is_empty() {
            self
        } else {
            self.filter(search.filter_for(&columns)?)
        };
        // sort the query
        Ok(sort
            .split_terminator(',')
            .map(|s| Sort::parse(s, &columns))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .fold(result, |select, s| s.order_by(select)))
    }
}
