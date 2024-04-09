use crate::service::Error;
use regex::Regex;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{ColumnTrait, ColumnType, Condition, EntityTrait, Iterable, Order};
use std::str::FromStr;
use std::sync::OnceLock;

pub struct Filter<T: EntityTrait> {
    operands: Operand<T>,
    operator: Operator,
}

pub struct Sort<T: EntityTrait> {
    pub field: T::Column,
    pub order: Order,
}

enum Operand<T: EntityTrait> {
    Simple(T::Column, String),
    Composite(Vec<Filter<T>>),
}

pub enum Operator {
    Equal,
    NotEqual,
    Like,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    And,
    Or,
}

impl<T: EntityTrait> Filter<T> {
    pub fn into_condition(&self) -> Condition {
        match &self.operands {
            Operand::Simple(col, v) => match self.operator {
                Operator::Equal => col.eq(v).into_condition(),
                Operator::NotEqual => col.ne(v).into_condition(),
                Operator::Like => col
                    .contains(v.replace('%', r"\%").replace('_', r"\_"))
                    .into_condition(),
                Operator::GreaterThan => col.gt(v).into_condition(),
                Operator::GreaterThanOrEqual => col.gte(v).into_condition(),
                Operator::LessThan => col.lt(v).into_condition(),
                Operator::LessThanOrEqual => col.lte(v).into_condition(),
                _ => unreachable!(),
            },
            Operand::Composite(v) => match self.operator {
                Operator::And => v
                    .iter()
                    .fold(Condition::all(), |and, t| and.add(t.into_condition())),
                Operator::Or => v
                    .iter()
                    .fold(Condition::any(), |or, t| or.add(t.into_condition())),
                _ => unreachable!(),
            },
        }
    }
}

/////////////////////////////////////////////////////////////////////////
// FromStr impls
/////////////////////////////////////////////////////////////////////////

// Form expected: "full text search({field}{op}{value})*"
impl<T: EntityTrait> FromStr for Filter<T> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const RE: &str = r"^(?<field>[[:word:]]+)(?<op>=|!=|~|>=|>|<=|<)(?<value>.*)$";
        static LOCK: OnceLock<Regex> = OnceLock::new();
        #[allow(clippy::unwrap_used)]
        let filter = LOCK.get_or_init(|| (Regex::new(RE).unwrap()));

        let escaped = s.replace(r"\&", "\x07");
        if escaped.contains('&') {
            Ok(Filter {
                operator: Operator::And,
                operands: Operand::Composite(
                    escaped
                        .split('&')
                        .map(Self::from_str)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            })
        } else if let Some(caps) = filter.captures(s) {
            let field = caps["field"].to_string();
            Ok(Filter {
                operands: Operand::Simple(
                    T::Column::from_str(&field).map_err(|_| {
                        Error::SearchSyntax(format!("Invalid field name for filter: '{field}'"))
                    })?,
                    caps["value"].replace('\x07', "&"),
                ),
                operator: Operator::from_str(&caps["op"])?,
            })
        } else {
            Ok(Filter {
                operator: Operator::Or,
                operands: Operand::Composite(
                    T::Column::iter()
                        .filter_map(|col| match col.def().get_column_type() {
                            ColumnType::String(_) | ColumnType::Text => Some(Filter {
                                operands: Operand::Simple(col, s.replace('\x07', "&")),
                                operator: Operator::Like,
                            }),
                            _ => None,
                        })
                        .collect(),
                ),
            })
        }
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
            field: T::Column::from_str(field).map_err(|_| {
                Error::SearchSyntax(format!("Invalid field name for sort: '{field}'"))
            })?,
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
            "|" => Ok(Operator::Or),
            "&" => Ok(Operator::And),
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
        assert!(Filter::<advisory::Entity>::from_str("something").is_ok());
        // Bad filters
        assert!(Filter::<advisory::Entity>::from_str("foo=bar").is_err());

        // There aren't many "bad filters" since random text is
        // considered a "full-text search" in which an OR clause is
        // constructed from a LIKE clause for all string fields in the
        // entity.

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
                .filter(Filter::<advisory::Entity>::from_str("location~f_o%o")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."location" LIKE E'%f\\_o\\%o%'"#
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
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("foo")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE "advisory"."identifier" LIKE '%foo%' OR "advisory"."location" LIKE '%foo%' OR "advisory"."sha256" LIKE '%foo%' OR "advisory"."title" LIKE '%foo%'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(Filter::<advisory::Entity>::from_str("foo&location=bar")?.into_condition())
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE ("advisory"."identifier" LIKE '%foo%' OR "advisory"."location" LIKE '%foo%' OR "advisory"."sha256" LIKE '%foo%' OR "advisory"."title" LIKE '%foo%') AND "advisory"."location" = 'bar'"#
        );
        assert_eq!(
            select
                .clone()
                .filter(
                    Filter::<advisory::Entity>::from_str(r"m\&m's&location=f\&oo&id=ba\&r")?
                        .into_condition()
                )
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string(),
            r#"SELECT "advisory"."id" FROM "advisory" WHERE ("advisory"."identifier" LIKE E'%m&m\'s%' OR "advisory"."location" LIKE E'%m&m\'s%' OR "advisory"."sha256" LIKE E'%m&m\'s%' OR "advisory"."title" LIKE E'%m&m\'s%') AND "advisory"."location" = 'f&oo' AND "advisory"."id" = 'ba&r'"#
        );

        Ok(())
    }
}
