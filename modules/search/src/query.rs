use crate::service::Error;
use human_date_parser::{from_human_time, ParseResult};
use regex::Regex;
use sea_orm::sea_query::{ConditionExpression, IntoCondition};
use sea_orm::{
    ColumnTrait, ColumnType, Condition, EntityTrait, Iterable, Order, QueryFilter, QueryOrder,
    Select, Value,
};
use std::fmt::Display;
use std::str::FromStr;
use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

/////////////////////////////////////////////////////////////////////////
// Public interface
/////////////////////////////////////////////////////////////////////////

pub trait Query<T: EntityTrait> {
    fn filtering(self, q: &str, sort: &str) -> Result<Select<T>, Error>;
}

impl<T: EntityTrait> Query<T> for Select<T> {
    fn filtering(self, q: &str, sort: &str) -> Result<Self, Error> {
        let id = T::Column::from_str("id")
            .map_err(|_| Error::SearchSyntax("Entity missing Id field".into()))?;
        Ok(if sort.is_empty() {
            self.filter(Filter::<T>::from_str(q)?).order_by_desc(id)
        } else {
            sort.split(',')
                .map(Sort::<T>::from_str)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .fold(self.filter(Filter::<T>::from_str(q)?), |select, s| {
                    select.order_by(s.field, s.order)
                })
                .order_by_desc(id)
        })
    }
}

/////////////////////////////////////////////////////////////////////////
// Internal types
/////////////////////////////////////////////////////////////////////////

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
                        col.like(v)
                    } else {
                        col.not_like(v)
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
            // We have collection of filters and/or queries
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

/////////////////////////////////////////////////////////////////////////
// Tests
/////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeDelta};
    use sea_orm::{QueryFilter, QuerySelect, QueryTrait};
    use test_log::test;
    use trustify_entity::advisory;

    fn test_advisory_operator(s: &str, expected: Operator) {
        match Filter::<advisory::Entity>::from_str(s) {
            Ok(Filter {
                operands: Operand::Composite(v),
                ..
            }) => assert_eq!(
                v[0].operator, expected,
                "The query '{s}' didn't resolve to {expected:?}"
            ),
            _ => panic!("The query '{s}' didn't resolve to {expected:?}"),
        }
    }

    #[test(tokio::test)]
    async fn filters() -> Result<(), anyhow::Error> {
        // Good filters
        test_advisory_operator("location=foo", Operator::Equal);
        test_advisory_operator("location!=foo", Operator::NotEqual);
        test_advisory_operator("location~foo", Operator::Like);
        test_advisory_operator("location!~foo", Operator::NotLike);
        test_advisory_operator("location>foo", Operator::GreaterThan);
        test_advisory_operator("location>=foo", Operator::GreaterThanOrEqual);
        test_advisory_operator("location<foo", Operator::LessThan);
        test_advisory_operator("location<=foo", Operator::LessThanOrEqual);

        // If a query matches the '{field}{op}{value}' regex, then the
        // first operand must resolve to a field on the Entity
        assert!(Filter::<advisory::Entity>::from_str("foo=bar").is_err());

        // There aren't many bad queries since random text is
        // considered a "full-text search" in which an OR clause is
        // constructed from a LIKE clause for all string fields in the
        // entity.
        test_advisory_operator("search the entity", Operator::Like);

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

    fn where_clause(query: &str) -> Result<String, anyhow::Error> {
        Ok(advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filter(Filter::<advisory::Entity>::from_str(query)?.into_condition())
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string()[45..]
            .to_string())
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
            r#""advisory"."location" LIKE '%foo%'"#
        );
        assert_eq!(
            where_clause("location~f_o%o")?,
            r#""advisory"."location" LIKE E'%f\\_o\\%o%'"#
        );
        assert_eq!(
            where_clause("location!~foo")?,
            r#""advisory"."location" NOT LIKE '%foo%'"#
        );
        assert_eq!(
            where_clause("location!~f_o%o")?,
            r#""advisory"."location" NOT LIKE E'%f\\_o\\%o%'"#
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
            where_clause("foo")?,
            r#""advisory"."identifier" LIKE '%foo%' OR "advisory"."location" LIKE '%foo%' OR "advisory"."sha256" LIKE '%foo%' OR "advisory"."title" LIKE '%foo%'"#
        );
        assert_eq!(
            where_clause("foo&location=bar")?,
            r#"("advisory"."identifier" LIKE '%foo%' OR "advisory"."location" LIKE '%foo%' OR "advisory"."sha256" LIKE '%foo%' OR "advisory"."title" LIKE '%foo%') AND "advisory"."location" = 'bar'"#
        );
        assert_eq!(
            where_clause(r"m\&m's&location=f\&oo&id=13")?,
            r#"("advisory"."identifier" LIKE E'%m&m\'s%' OR "advisory"."location" LIKE E'%m&m\'s%' OR "advisory"."sha256" LIKE E'%m&m\'s%' OR "advisory"."title" LIKE E'%m&m\'s%') AND "advisory"."location" = 'f&oo' AND "advisory"."id" = 13"#
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
            where_clause("a|b|c")?,
            r#""advisory"."identifier" LIKE '%a%' OR "advisory"."location" LIKE '%a%' OR "advisory"."sha256" LIKE '%a%' OR "advisory"."title" LIKE '%a%' OR "advisory"."identifier" LIKE '%b%' OR "advisory"."location" LIKE '%b%' OR "advisory"."sha256" LIKE '%b%' OR "advisory"."title" LIKE '%b%' OR "advisory"."identifier" LIKE '%c%' OR "advisory"."location" LIKE '%c%' OR "advisory"."sha256" LIKE '%c%' OR "advisory"."title" LIKE '%c%'"#
        );
        assert_eq!(
            where_clause("a|b&id=1")?,
            r#"("advisory"."identifier" LIKE '%a%' OR "advisory"."location" LIKE '%a%' OR "advisory"."sha256" LIKE '%a%' OR "advisory"."title" LIKE '%a%' OR "advisory"."identifier" LIKE '%b%' OR "advisory"."location" LIKE '%b%' OR "advisory"."sha256" LIKE '%b%' OR "advisory"."title" LIKE '%b%') AND "advisory"."id" = 1"#
        );
        assert_eq!(
            where_clause("a&b")?,
            r#"("advisory"."identifier" LIKE '%a%' OR "advisory"."location" LIKE '%a%' OR "advisory"."sha256" LIKE '%a%' OR "advisory"."title" LIKE '%a%') AND ("advisory"."identifier" LIKE '%b%' OR "advisory"."location" LIKE '%b%' OR "advisory"."sha256" LIKE '%b%' OR "advisory"."title" LIKE '%b%')"#
        );
        assert_eq!(
            where_clause("here&location!~there|hereford")?,
            r#"("advisory"."identifier" LIKE '%here%' OR "advisory"."location" LIKE '%here%' OR "advisory"."sha256" LIKE '%here%' OR "advisory"."title" LIKE '%here%') AND ("advisory"."location" NOT LIKE '%there%' AND "advisory"."location" NOT LIKE '%hereford%')"#
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
}
