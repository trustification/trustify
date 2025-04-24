use super::{Columns, Error};
use sea_orm::{Order, QueryOrder};
use sea_query::SimpleExpr;

pub(crate) struct Sort {
    field: SimpleExpr,
    order: Order,
}

impl Sort {
    pub(crate) fn order_by<T: QueryOrder>(self, stmt: T) -> T {
        stmt.order_by(self.field, self.order)
    }
    pub(crate) fn parse(s: &str, columns: &Columns) -> Result<Self, Error> {
        let lower = s.to_lowercase();
        let (field, order) = match lower.rsplit_once(':') {
            Some((f, dir @ ("asc" | "desc"))) => (f, dir),
            _ => (s, "asc"),
        };
        match columns.translate(field, order, "") {
            Some(s) => Sort::parse(&s, columns),
            None => Ok(Self {
                field: columns.for_field(field)?.0,
                order: match order {
                    "asc" => Order::Asc,
                    "desc" => Order::Desc,
                    _ => unreachable!(),
                },
            }),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests::*;
    use super::super::*;
    use super::*;

    use sea_orm::{ColumnType, ColumnTypeTrait};
    use sea_query::StringLen;
    use test_log::test;

    #[test(tokio::test)]
    async fn sorts() -> Result<(), anyhow::Error> {
        let columns = advisory::Entity.columns();
        // Good sorts
        assert!(Sort::parse("location", &columns).is_ok());
        assert!(Sort::parse("location:asc", &columns).is_ok());
        assert!(Sort::parse("location:desc", &columns).is_ok());
        assert!(Sort::parse("Location", &columns).is_ok());
        assert!(Sort::parse("Location:Asc", &columns).is_ok());
        assert!(Sort::parse("Location:Desc", &columns).is_ok());
        assert!(Sort::parse("purl:foo:desc", &columns).is_ok());
        assert!(Sort::parse("purl:asc:desc", &columns).is_ok());
        // Bad sorts
        assert!(Sort::parse("foo:", &columns).is_err());
        assert!(Sort::parse(":foo", &columns).is_err());
        match Sort::parse("foo", &columns) {
            Ok(_) => panic!("invalid field"),
            Err(e) => log::error!("{e}"),
        }
        match Sort::parse("location:foo", &columns) {
            Ok(_) => panic!("invalid json field"),
            Err(e) => log::error!("{e}"),
        }
        match Sort::parse("location:asc:foo", &columns) {
            Ok(_) => panic!("invalid sort direction"),
            Err(e) => log::error!("{e}"),
        }
        assert!(Sort::parse("location:asc:foo", &columns).is_err());

        // Good sorts with other columns
        assert!(
            Sort::parse(
                "foo",
                &advisory::Entity
                    .columns()
                    .add_column("foo", ColumnType::String(StringLen::None).def())
            )
            .is_ok()
        );

        // Bad sorts with other columns
        assert!(
            Sort::parse(
                "bar",
                &advisory::Entity
                    .columns()
                    .add_column("foo", ColumnType::String(StringLen::None).def())
            )
            .is_err()
        );

        Ok(())
    }
}
