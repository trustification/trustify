use std::str::FromStr;

use sea_orm::sea_query::IntoCondition;
use sea_orm::{ColumnTrait, Condition, EntityTrait, Order};

use crate::service::Error;

pub struct Filter<T: EntityTrait> {
    field: T::Column,
    operator: Operator,
    value: String,
}

pub struct Sort<T: EntityTrait> {
    pub field: T::Column,
    pub order: Order,
}

pub enum Operator {
    Equal,
    NotEqual,
    Like,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

impl<T: EntityTrait> Filter<T> {
    pub fn into_condition(&self) -> Condition {
        let col = self.field;
        let v = self.value.clone();
        let expr = match self.operator {
            Operator::Equal => col.eq(v),
            Operator::NotEqual => col.ne(v),
            Operator::Like => col.contains(v),
            Operator::GreaterThan => col.gt(v),
            Operator::GreaterThanOrEqual => col.gte(v),
            Operator::LessThan => col.lt(v),
            Operator::LessThanOrEqual => col.lte(v),
        };
        expr.into_condition()
    }
}

/////////////////////////////////////////////////////////////////////////
// FromStr impls
/////////////////////////////////////////////////////////////////////////

impl<T: EntityTrait> FromStr for Filter<T> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = r"^(?<field>[[:word:]]+)(?<op>=|!=|~|>=|>|<=|<)(?<value>.*)$";
        #[allow(clippy::unwrap_used)]
        let caps = regex::Regex::new(re)
            .unwrap()
            .captures(s)
            .ok_or(Error::SearchSyntax(format!("Invalid filter: '{s}'")))?;
        let field = caps["field"].to_string();
        Ok(Filter {
            field: T::Column::from_str(&field)
                .map_err(|_| Error::SearchSyntax(format!("Invalid field name: '{field}'")))?,
            operator: Operator::from_str(&caps["op"])?,
            value: caps["value"].into(),
        })
    }
}

impl<T: EntityTrait> FromStr for Sort<T> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        let (field, order) = match s.split(':').collect::<Vec<_>>()[..] {
            [f, "asc"] | [f] => (f, Order::Asc),
            [f, "desc"] => (f, Order::Desc),
            _ => {
                return Err(Error::SearchSyntax(format!("Invalid sort: '{s}'")));
            }
        };
        Ok(Self {
            field: T::Column::from_str(field)
                .map_err(|_| Error::SearchSyntax(format!("Invalid field name: '{field}'")))?,
            order,
        })
    }
}

impl FromStr for Operator {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "=" => Ok(Operator::Equal),
            "!=" => Ok(Operator::NotEqual),
            "~" => Ok(Operator::Like),
            ">" => Ok(Operator::GreaterThan),
            ">=" => Ok(Operator::GreaterThanOrEqual),
            "<" => Ok(Operator::LessThan),
            "<=" => Ok(Operator::LessThanOrEqual),
            _ => Err(Error::SearchSyntax(format!("Invalid operator: '{s}'"))),
        }
    }
}

/////////////////////////////////////////////////////////////////////////
// Tests
/////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{QueryFilter, QuerySelect, QueryTrait};
    use test_log::test;
    use trustify_entity::advisory;

    #[test(tokio::test)]
    async fn filters() -> Result<(), anyhow::Error> {
        // Good filters
        assert!(Filter::<advisory::Entity>::from_str("location=foo").is_ok());
        assert!(Filter::<advisory::Entity>::from_str("location!=foo").is_ok());
        assert!(Filter::<advisory::Entity>::from_str("location~foo").is_ok());
        assert!(Filter::<advisory::Entity>::from_str("location>foo").is_ok());
        assert!(Filter::<advisory::Entity>::from_str("location>=foo").is_ok());
        assert!(Filter::<advisory::Entity>::from_str("location<foo").is_ok());
        assert!(Filter::<advisory::Entity>::from_str("location<=foo").is_ok());
        // Bad filters
        assert!(Filter::<advisory::Entity>::from_str("foo=bar").is_err());
        assert!(Filter::<advisory::Entity>::from_str("location@foo").is_err());
        assert!(Filter::<advisory::Entity>::from_str("location = foo").is_err());
        assert!(Filter::<advisory::Entity>::from_str("=").is_err());
        assert!(Filter::<advisory::Entity>::from_str("").is_err());

        Ok(())
    }

    #[test(tokio::test)]
    async fn sorts() -> Result<(), anyhow::Error> {
        // Good sorts
        assert!(Sort::<advisory::Entity>::from_str("location").is_ok());
        assert!(Sort::<advisory::Entity>::from_str("location:asc").is_ok());
        assert!(Sort::<advisory::Entity>::from_str("location:desc").is_ok());
        assert!(Sort::<advisory::Entity>::from_str("Location").is_ok());
        assert!(Sort::<advisory::Entity>::from_str("Location:Asc").is_ok());
        assert!(Sort::<advisory::Entity>::from_str("Location:Desc").is_ok());
        // Bad sorts
        assert!(Sort::<advisory::Entity>::from_str("foo").is_err());
        assert!(Sort::<advisory::Entity>::from_str("foo:").is_err());
        assert!(Sort::<advisory::Entity>::from_str(":foo").is_err());
        assert!(Sort::<advisory::Entity>::from_str("location:foo").is_err());
        assert!(Sort::<advisory::Entity>::from_str("location:asc:foo").is_err());

        Ok(())
    }

    #[test(tokio::test)]
    async fn conditions() -> Result<(), anyhow::Error> {
        let select = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id);
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("location=foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" = 'foo'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("location!=foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" <> 'foo'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("location~foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" LIKE '%foo%'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("location>foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" > 'foo'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("location>=foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" >= 'foo'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("location<foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" < 'foo'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("location<=foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" <= 'foo'"#
        );

        Ok(())
    }
}
