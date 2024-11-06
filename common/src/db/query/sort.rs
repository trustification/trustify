use super::{Columns, Error};
use sea_orm::{Order, QueryOrder};
use sea_query::Expr;

pub(crate) struct Sort {
    field: Expr,
    order: Order,
}

impl Sort {
    pub(crate) fn order_by<T: QueryOrder>(self, stmt: T) -> T {
        stmt.order_by(self.field, self.order)
    }
    pub(crate) fn parse(s: &str, columns: &Columns) -> Result<Self, Error> {
        let (field, order) = match s.split(':').collect::<Vec<_>>()[..] {
            [f] => (f, String::from("asc")),
            [f, dir] => (f, dir.to_lowercase()),
            _ => {
                return Err(Error::SearchSyntax(format!("Invalid sort: '{s}'")));
            }
        };
        match columns.translate(field, &order, "") {
            Some(s) => Sort::parse(&s, columns),
            None => Ok(Self {
                field: columns
                    .for_field(field)
                    .ok_or(Error::SearchSyntax(format!(
                        "Invalid sort field: '{field}'"
                    )))?
                    .0,
                order: match order.as_str() {
                    "asc" => Order::Asc,
                    "desc" => Order::Desc,
                    dir => {
                        return Err(Error::SearchSyntax(format!(
                            "Invalid sort direction: '{dir}'"
                        )));
                    }
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
        // Bad sorts
        assert!(Sort::parse("foo", &columns).is_err());
        assert!(Sort::parse("foo:", &columns).is_err());
        assert!(Sort::parse(":foo", &columns).is_err());
        assert!(Sort::parse("location:foo", &columns).is_err());
        assert!(Sort::parse("location:asc:foo", &columns).is_err());

        // Good sorts with other columns
        assert!(Sort::parse(
            "foo",
            &advisory::Entity
                .columns()
                .add_column("foo", ColumnType::String(StringLen::None).def())
        )
        .is_ok());

        // Bad sorts with other columns
        assert!(Sort::parse(
            "bar",
            &advisory::Entity
                .columns()
                .add_column("foo", ColumnType::String(StringLen::None).def())
        )
        .is_err());

        Ok(())
    }
}
