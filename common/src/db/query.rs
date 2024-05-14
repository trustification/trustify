use human_date_parser::{from_human_time, ParseResult};
use regex::Regex;
use sea_orm::sea_query::{extension::postgres::PgExpr, ConditionExpression, IntoCondition};
use sea_orm::{
    ColumnTrait, ColumnType, Condition, EntityName, EntityTrait, Iden, Iterable, Order,
    PrimaryKeyToColumn, QueryFilter, QueryOrder, QueryTrait, Select, Value,
};
use std::fmt::Display;
use std::str::FromStr;
use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};
use utoipa::IntoParams;

/////////////////////////////////////////////////////////////////////////
// Public interface
/////////////////////////////////////////////////////////////////////////

#[derive(
    Clone,
    Default,
    Debug,
    serde::Deserialize,
    serde::Serialize,
    utoipa::ToSchema,
    utoipa::IntoParams,
)]
#[serde(rename_all = "camelCase")]
pub struct SearchOptions {
    /// The search filter
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    /// Sort options
    pub sort: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("query syntax error: {0}")]
    SearchSyntax(String),
}

pub trait Query<T: EntityTrait> {
    fn filtering(self, search: SearchOptions) -> Result<Select<T>, Error>;
}

impl<T: EntityTrait> Query<T> for Select<T> {
    fn filtering(self, search: SearchOptions) -> Result<Self, Error> {
        let SearchOptions { q, sort } = &search;

        let mut result = if q.is_empty() {
            self
        } else {
            self.filter(Filter::<T>::from_str(q)?)
        };

        if !sort.is_empty() {
            result = sort
                .split(',')
                .map(Sort::<T>::from_str)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .fold(result, |select, s| select.order_by(s.field, s.order));
        };

        Ok(maintain_order(result))
    }
}

/////////////////////////////////////////////////////////////////////////
// Internal types
/////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct Filter<T: EntityTrait> {
    operands: Operand<T>,
    operator: Operator,
}

struct Sort<T: EntityTrait> {
    field: T::Column,
    order: Order,
}

/////////////////////////////////////////////////////////////////////////
// SeaORM impls
/////////////////////////////////////////////////////////////////////////

impl<T: EntityTrait> IntoCondition for Filter<T> {
    fn into_condition(self) -> Condition {
        match self.operands {
            Operand::Simple(col, v) => match self.operator {
                Operator::Equal => col.eq(v),
                Operator::NotEqual => col.ne(v),
                op @ (Operator::Like | Operator::NotLike) => {
                    let v = format!(
                        "%{}%",
                        v.unwrap::<String>().replace('%', r"\%").replace('_', r"\_")
                    );
                    if op == Operator::Like {
                        col.into_expr().ilike(v)
                    } else {
                        col.into_expr().not_ilike(v)
                    }
                }
                Operator::GreaterThan => col.gt(v),
                Operator::GreaterThanOrEqual => col.gte(v),
                Operator::LessThan => col.lt(v),
                Operator::LessThanOrEqual => col.lte(v),
                _ => unreachable!(),
            }
            .into_condition(),
            Operand::Composite(v) => match self.operator {
                Operator::And => v.into_iter().fold(Condition::all(), |and, f| and.add(f)),
                Operator::Or => v.into_iter().fold(Condition::any(), |or, f| or.add(f)),
                _ => unreachable!(),
            },
        }
    }
}

impl<T: EntityTrait> From<Filter<T>> for ConditionExpression {
    fn from(f: Filter<T>) -> Self {
        ConditionExpression::Condition(f.into_condition())
    }
}

/////////////////////////////////////////////////////////////////////////
// FromStr impls
/////////////////////////////////////////////////////////////////////////

impl<T: EntityTrait> FromStr for Filter<T> {
    type Err = Error;

    /// Create a Filter for a given Entity from a string
    ///
    /// Form expected: `{search}*({field}{op}{value})*`
    ///
    /// Multiple queries and/or filters should be `&`-delimited
    ///
    /// The `{search}` text will result in an OR clause of LIKE
    /// clauses for each [String] field in the associated
    /// [Entity](sea_orm::EntityTrait). Optional filters of the form
    /// `{field}{op}{value}` may further constrain the results. Each
    /// `{field}` must name an actual
    /// [Column](sea_orm::EntityTrait::Column) variant.
    ///
    /// Both `{search}` and `{value}` may contain `|`-delimited
    /// alternate values that will result in an OR clause. Any `|` or
    /// `&` in the query should be escaped with a backslash, e.g. `\|`
    /// or `\&`.
    ///
    /// `{op}` should be one of `=`, `!=`, `~`, `!~, `>=`, `>`, `<=`,
    /// or `<`.
    ///
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const RE: &str = r"^(?<field>[[:word:]]+)(?<op>=|!=|~|!~|>=|>|<=|<)(?<value>.*)$";
        static LOCK: OnceLock<Regex> = OnceLock::new();
        #[allow(clippy::unwrap_used)]
        let filter = LOCK.get_or_init(|| (Regex::new(RE).unwrap()));

        let encoded = encode(s);
        if encoded.contains('&') {
            // We have a collection of filters and/or queries
            Ok(Filter {
                operator: Operator::And,
                operands: Operand::Composite(
                    encoded
                        .split('&')
                        .map(Self::from_str)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            })
        } else if let Some(caps) = filter.captures(&encoded) {
            // We have a filter: {field}{op}{value}
            let field = &caps["field"];
            let col = T::Column::from_str(field).map_err(|_| {
                Error::SearchSyntax(format!("Invalid field name for filter: '{field}'"))
            })?;
            let def = col.def();
            let operator = Operator::from_str(&caps["op"])?;
            Ok(Filter {
                operator: match operator {
                    Operator::NotLike | Operator::NotEqual => Operator::And,
                    _ => Operator::Or,
                },
                operands: Operand::Composite(
                    caps["value"]
                        .split('|')
                        .map(decode)
                        .map(|s| envalue(&s, def.get_column_type()))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .map(|v| Filter {
                            operands: Operand::Simple(col, v),
                            operator,
                        })
                        .collect(),
                ),
            })
        } else {
            // We have a full-text search query
            Ok(Filter {
                operator: Operator::Or,
                operands: Operand::Composite(
                    encoded
                        .split('|')
                        .flat_map(|s| {
                            T::Column::iter().filter_map(|col| match col.def().get_column_type() {
                                ColumnType::String(_) | ColumnType::Text => Some(Filter {
                                    operands: Operand::<T>::Simple(col, decode(s).into()),
                                    operator: Operator::Like,
                                }),
                                _ => None,
                            })
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
            "!~" => Ok(Operator::NotLike),
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
// Internal helpers
/////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
enum Operand<T: EntityTrait> {
    Simple(T::Column, Value),
    Composite(Vec<Filter<T>>),
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum Operator {
    Equal,
    NotEqual,
    Like,
    NotLike,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    And,
    Or,
}

fn encode(s: &str) -> String {
    s.replace(r"\&", "\x07").replace(r"\|", "\x08")
}

fn decode(s: &str) -> String {
    s.replace('\x07', "&").replace('\x08', "|")
}

fn envalue(s: &str, ct: &ColumnType) -> Result<Value, Error> {
    fn err(e: impl Display) -> Error {
        Error::SearchSyntax(format!(r#"conversion error: "{e}""#))
    }
    Ok(match ct {
        ColumnType::Integer => s.parse::<i32>().map_err(err)?.into(),
        ColumnType::TimestampWithTimeZone => {
            if let Ok(odt) = OffsetDateTime::parse(s, &Rfc3339) {
                odt.into()
            } else if let Ok(d) = Date::parse(s, &format_description!("[year]-[month]-[day]")) {
                d.into()
            } else if let Ok(human) = from_human_time(s) {
                match human {
                    ParseResult::DateTime(dt) => dt.into(),
                    ParseResult::Date(d) => d.into(),
                    ParseResult::Time(t) => t.into(),
                }
            } else {
                s.into()
            }
        }
        _ => s.into(),
    })
}

fn maintain_order<T: EntityTrait>(stmt: Select<T>) -> Select<T> {
    let binding = T::default();
    let table = binding.table_name();
    let s = stmt.build(sea_orm::DatabaseBackend::Postgres).to_string();
    let orderby = match s.rsplit_once(" ORDER BY ") {
        Some((_, v)) => v,
        None => "",
    };
    T::PrimaryKey::iter().fold(stmt, |stmt, pk| {
        let col = pk.into_column();
        let pat = format!(r#""{}"."{}""#, table, col.to_string());
        if orderby.contains(&pat) {
            stmt
        } else {
            stmt.order_by_desc(col)
        }
    })
}

/////////////////////////////////////////////////////////////////////////
// Tests
/////////////////////////////////////////////////////////////////////////

/*
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeDelta};
    use sea_orm::{QueryFilter, QuerySelect, QueryTrait};
    use test_log::test;

    #[test(tokio::test)]
    async fn filters() -> Result<(), anyhow::Error> {
        let test = |s: &str, expected: Operator| match Filter::<advisory::Entity>::from_str(s) {
            Ok(Filter {
                operands: Operand::Composite(v),
                ..
            }) => assert_eq!(
                v[0].operator, expected,
                "The query '{s}' didn't resolve to {expected:?}"
            ),
            _ => panic!("The query '{s}' didn't resolve to {expected:?}"),
        };

        // Good filters
        test("location=foo", Operator::Equal);
        test("location!=foo", Operator::NotEqual);
        test("location~foo", Operator::Like);
        test("location!~foo", Operator::NotLike);
        test("location>foo", Operator::GreaterThan);
        test("location>=foo", Operator::GreaterThanOrEqual);
        test("location<foo", Operator::LessThan);
        test("location<=foo", Operator::LessThanOrEqual);

        // If a query matches the '{field}{op}{value}' regex, then the
        // first operand must resolve to a field on the Entity
        assert!(Filter::<advisory::Entity>::from_str("foo=bar").is_err());

        // There aren't many bad queries since random text is
        // considered a "full-text search" in which an OR clause is
        // constructed from a LIKE clause for all string fields in the
        // entity.
        test("search the entity", Operator::Like);

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
        assert_eq!(
            where_clause("location=foo")?,
            r#""advisory"."location" = 'foo'"#
        );
        assert_eq!(
            where_clause("location!=foo")?,
            r#""advisory"."location" <> 'foo'"#
        );
        assert_eq!(
            where_clause("location~foo")?,
            r#""advisory"."location" ILIKE '%foo%'"#
        );
        assert_eq!(
            where_clause("location~f_o%o")?,
            r#""advisory"."location" ILIKE E'%f\\_o\\%o%'"#
        );
        assert_eq!(
            where_clause("location!~foo")?,
            r#""advisory"."location" NOT ILIKE '%foo%'"#
        );
        assert_eq!(
            where_clause("location!~f_o%o")?,
            r#""advisory"."location" NOT ILIKE E'%f\\_o\\%o%'"#
        );
        assert_eq!(
            where_clause("location>foo")?,
            r#""advisory"."location" > 'foo'"#
        );
        assert_eq!(
            where_clause("location>=foo")?,
            r#""advisory"."location" >= 'foo'"#
        );
        assert_eq!(
            where_clause("location<foo")?,
            r#""advisory"."location" < 'foo'"#
        );
        assert_eq!(
            where_clause("location<=foo")?,
            r#""advisory"."location" <= 'foo'"#
        );
        assert_eq!(
            where_clause("location=a|b|c")?,
            r#""advisory"."location" = 'a' OR "advisory"."location" = 'b' OR "advisory"."location" = 'c'"#
        );
        assert_eq!(
            where_clause("location!=a|b|c")?,
            r#""advisory"."location" <> 'a' AND "advisory"."location" <> 'b' AND "advisory"."location" <> 'c'"#
        );
        assert_eq!(
            where_clause(r"location=foo|\&\|")?,
            r#""advisory"."location" = 'foo' OR "advisory"."location" = '&|'"#
        );
        assert_eq!(
            where_clause("published>2023-11-03T23:20:50.52Z")?,
            r#""advisory"."published" > '2023-11-03 23:20:50.520000 +00:00'"#
        );
        assert_eq!(
            where_clause("published>2023-11-03T23:20:51-04:00")?,
            r#""advisory"."published" > '2023-11-03 23:20:51.000000 -04:00'"#
        );
        assert_eq!(
            where_clause("published>2023-11-03")?,
            r#""advisory"."published" > '2023-11-03'"#
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn complex_ilikes() -> Result<(), anyhow::Error> {
        //
        // I broke these assertions out into their own test as they
        // resulted in very conservative parentheses when moving from
        // LIKE to ILIKE. I think the extra parens are harmless, but I
        // suspect it may be a bug that LIKE and ILIKE operators are
        // treated differently, as their precedence should be the same
        // on PostgreSQL.
        //
        // Upstream issue: https://github.com/SeaQL/sea-query/issues/776
        // See also https://github.com/SeaQL/sea-query/pull/675

        assert_eq!(
            where_clause("foo")?,
            r#"("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%')"#
        );
        assert_eq!(
            where_clause("foo&location=bar")?,
            r#"(("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%')) AND "advisory"."location" = 'bar'"#
        );
        assert_eq!(
            where_clause(r"m\&m's&location=f\&oo&id=13")?,
            r#"(("advisory"."location" ILIKE E'%m&m\'s%') OR ("advisory"."title" ILIKE E'%m&m\'s%')) AND "advisory"."location" = 'f&oo' AND "advisory"."id" = 13"#
        );
        assert_eq!(
            where_clause("a|b|c")?,
            r#"("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%') OR ("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%') OR ("advisory"."location" ILIKE '%c%') OR ("advisory"."title" ILIKE '%c%')"#
        );
        assert_eq!(
            where_clause("a|b&id=1")?,
            r#"(("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%') OR ("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%')) AND "advisory"."id" = 1"#
        );
        assert_eq!(
            where_clause("a&b")?,
            r#"(("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%')) AND (("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%'))"#
        );
        assert_eq!(
            where_clause("here&location!~there|hereford")?,
            r#"(("advisory"."location" ILIKE '%here%') OR ("advisory"."title" ILIKE '%here%')) AND (("advisory"."location" NOT ILIKE '%there%') AND ("advisory"."location" NOT ILIKE '%hereford%'))"#
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn human_time() -> Result<(), anyhow::Error> {
        let now = Local::now();
        let yesterday = (now - TimeDelta::try_days(1).unwrap()).format("%Y-%m-%d");
        let last_week = (now - TimeDelta::try_days(7).unwrap()).format("%Y-%m-%d");
        let three_days_ago = (now - TimeDelta::try_days(3).unwrap()).format("%Y-%m-%d");
        assert_eq!(
            where_clause("published<yesterday")?,
            format!(r#""advisory"."published" < '{yesterday}'"#)
        );
        assert_eq!(
            where_clause("published>last week")?,
            format!(r#""advisory"."published" > '{last_week}'"#)
        );
        let wc = where_clause("published=3 days ago")?;
        let expected = &format!(r#""advisory"."published" = '{three_days_ago} "#);
        assert!(
            wc.starts_with(expected),
            "expected '{wc}' to start with '{expected}'"
        );

        // Other possibilities, assuming it's New Year's day, 2010
        //
        // "Today 18:30" = "2010-01-01 18:30:00",
        // "Yesterday 18:30" = "2009-12-31 18:30:00",
        // "Tomorrow 18:30" = "2010-01-02 18:30:00",
        // "Overmorrow 18:30" = "2010-01-03 18:30:00",
        // "2022-11-07 13:25:30" = "2022-11-07 13:25:30",
        // "15:20 Friday" = "2010-01-08 15:20:00",
        // "This Friday 17:00" = "2010-01-08 17:00:00",
        // "13:25, Next Tuesday" = "2010-01-12 13:25:00",
        // "Last Friday at 19:45" = "2009-12-25 19:45:00",
        // "Next week" = "2010-01-08 00:00:00",
        // "This week" = "2010-01-01 00:00:00",
        // "Last week" = "2009-12-25 00:00:00",
        // "Next week Monday" = "2010-01-04 00:00:00",
        // "This week Friday" = "2010-01-01 00:00:00",
        // "This week Monday" = "2009-12-28 00:00:00",
        // "Last week Tuesday" = "2009-12-22 00:00:00",
        // "In 3 days" = "2010-01-04 00:00:00",
        // "In 2 hours" = "2010-01-01 02:00:00",
        // "In 5 minutes and 30 seconds" = "2010-01-01 00:05:30",
        // "10 seconds ago" = "2009-12-31 23:59:50",
        // "10 hours and 5 minutes ago" = "2009-12-31 13:55:00",
        // "2 hours, 32 minutes and 7 seconds ago" = "2009-12-31 21:27:53",
        // "1 years, 2 months, 3 weeks, 5 days, 8 hours, 17 minutes and 45 seconds ago" =
        //     "2008-10-07 16:42:15",
        // "1 year, 1 month, 1 week, 1 day, 1 hour, 1 minute and 1 second ago" = "2008-11-23 22:58:59",
        // "A year ago" = "2009-01-01 00:00:00",
        // "A month ago" = "2009-12-01 00:00:00",
        // "A week ago" = "2009-12-25 00:00:00",
        // "A day ago" = "2009-12-31 00:00:00",
        // "An hour ago" = "2009-12-31 23:00:00",
        // "A minute ago" = "2009-12-31 23:59:00",
        // "A second ago" = "2009-12-31 23:59:59",
        // "now" = "2010-01-01 00:00:00",
        // "Overmorrow" = "2010-01-03 00:00:00"

        Ok(())
    }

    #[test(tokio::test)]
    async fn default_filtering() -> Result<(), anyhow::Error> {
        let expected_asc = advisory::Entity::find()
            .filter(advisory::Column::Location.eq("foo"))
            .order_by_asc(advisory::Column::Id)
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        let expected_desc = advisory::Entity::find()
            .filter(advisory::Column::Location.eq("foo"))
            .order_by_desc(advisory::Column::Id)
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();

        // already ordering by ID ASC, so leave it alone
        let actual = advisory::Entity::find()
            .filter(advisory::Column::Location.eq("foo"))
            .order_by_asc(advisory::Column::Id)
            .filtering(SearchOptions::default())?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(actual, expected_asc);

        // No ordering, so order by ID DESC
        let actual = advisory::Entity::find()
            .filter(advisory::Column::Location.eq("foo"))
            .filtering(SearchOptions::default())?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(actual, expected_desc);

        // already ordering by ID DESC, so don't add another
        let actual = advisory::Entity::find()
            .filter(advisory::Column::Location.eq("foo"))
            .order_by_desc(advisory::Column::Id)
            .filtering(SearchOptions::default())?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(actual, expected_desc);
        Ok(())
    }

    #[test(tokio::test)]
    async fn missing_id() -> Result<(), anyhow::Error> {
        mod missing_id {
            use sea_orm::entity::prelude::*;

            #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
            #[sea_orm(table_name = "nothing")]
            pub struct Model {
                #[sea_orm(primary_key)]
                pub at_all: i32,
            }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }

        let expected = missing_id::Entity::find()
            .order_by_desc(missing_id::Column::AtAll)
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        let actual = missing_id::Entity::find()
            .filtering(SearchOptions::default())?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(expected, actual);

        Ok(())
    }

    #[test(tokio::test)]
    async fn composite_key() -> Result<(), anyhow::Error> {
        mod composite_key {
            use sea_orm::entity::prelude::*;

            #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
            #[sea_orm(table_name = "nothing")]
            pub struct Model {
                #[sea_orm(primary_key)]
                pub more: i32,
                #[sea_orm(primary_key)]
                pub at_all: i32,
            }
            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}
            impl ActiveModelBehavior for ActiveModel {}
        }

        let expected = composite_key::Entity::find()
            .order_by_desc(composite_key::Column::More)
            .order_by_desc(composite_key::Column::AtAll)
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        let actual = composite_key::Entity::find()
            .filtering(SearchOptions::default())?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(expected, actual);

        let expected_asc = composite_key::Entity::find()
            .order_by_asc(composite_key::Column::AtAll)
            .order_by_asc(composite_key::Column::More)
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        let actual = composite_key::Entity::find()
            .order_by_asc(composite_key::Column::AtAll)
            .order_by_asc(composite_key::Column::More)
            .filtering(SearchOptions::default())?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(expected_asc, actual);

        Ok(())
    }

    /////////////////////////////////////////////////////////////////////////
    // Test helpers
    /////////////////////////////////////////////////////////////////////////

    fn where_clause(query: &str) -> Result<String, anyhow::Error> {
        Ok(advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filter(Filter::<advisory::Entity>::from_str(query)?.into_condition())
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string()[45..]
            .to_string())
    }

    mod advisory {
        use sea_orm::entity::prelude::*;
        use time::OffsetDateTime;

        #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
        #[sea_orm(table_name = "advisory")]
        pub struct Model {
            #[sea_orm(primary_key)]
            pub id: i32,
            pub location: String,
            pub title: String,
            pub published: Option<OffsetDateTime>,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }
}


 */
