use super::{q, Columns, Error};
use human_date_parser::{from_human_time, ParseResult};
use sea_orm::sea_query::{extension::postgres::PgExpr, ConditionExpression, IntoCondition};
use sea_orm::{sea_query, ColumnType, Condition, IntoSimpleExpr, Value as SeaValue};
use sea_query::{BinOper, Expr, Keyword, SimpleExpr};
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) struct Filter {
    operands: Operand,
    operator: Operator,
}

impl Filter {
    pub(crate) fn all(filters: Vec<Filter>) -> Self {
        Filter {
            operator: Operator::And,
            operands: Operand::Composite(filters),
        }
    }
}

// From a filter string of the form {field}{op}{value}
impl TryFrom<(&str, Operator, &Vec<String>, &Columns)> for Filter {
    type Error = Error;
    fn try_from(tuple: (&str, Operator, &Vec<String>, &Columns)) -> Result<Self, Self::Error> {
        let (ref field, operator, values, columns) = tuple;
        let (expr, col_def) = columns.for_field(field).ok_or(Error::SearchSyntax(format!(
            "Invalid field name for filter: '{field}'"
        )))?;
        Ok(Filter {
            operator: match operator {
                Operator::NotLike | Operator::NotEqual => Operator::And,
                _ => Operator::Or,
            },
            operands: Operand::Composite(
                values
                    .iter()
                    .map(|s| Arg::parse(s, col_def.get_column_type()).map(|v| (s, v)))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .flat_map(
                        |(s, v)| match columns.translate(field, &operator.to_string(), s) {
                            Some(x) => q(&x).filter_for(columns),
                            None => Ok(Filter {
                                operands: Operand::Simple(expr.clone(), v),
                                operator,
                            }),
                        },
                    )
                    .collect(),
            ),
        })
    }
}

// From a '|'-delimited query string denoting a full-text search
impl TryFrom<(&Vec<String>, &Columns)> for Filter {
    type Error = Error;
    fn try_from(tuple: (&Vec<String>, &Columns)) -> Result<Self, Self::Error> {
        let (values, columns) = tuple;
        Ok(Filter {
            operator: Operator::Or,
            operands: Operand::Composite(
                values
                    .iter()
                    .flat_map(|s| {
                        // Create a LIKE filter for all the string-ish columns
                        columns.iter().filter_map(move |(col_ref, col_def)| {
                            match col_def.get_column_type() {
                                ColumnType::String(_) | ColumnType::Text => Some(Filter {
                                    operands: Operand::Simple(
                                        Expr::col(col_ref.clone()),
                                        Arg::Value(SeaValue::from(s)),
                                    ),
                                    operator: Operator::Like,
                                }),
                                _ => None,
                            }
                        })
                    })
                    .collect(),
            ),
        })
    }
}

impl IntoCondition for Filter {
    fn into_condition(self) -> Condition {
        match self.operands {
            Operand::Simple(expr, v) => match self.operator {
                Operator::Equal => match v {
                    Arg::Null => expr.is_null(),
                    v => expr.binary(BinOper::Equal, v.into_simple_expr()),
                },
                Operator::NotEqual => match v {
                    Arg::Null => expr.is_not_null(),
                    v => expr.binary(BinOper::NotEqual, v.into_simple_expr()),
                },
                Operator::GreaterThan => expr.binary(BinOper::GreaterThan, v.into_simple_expr()),
                Operator::GreaterThanOrEqual => {
                    expr.binary(BinOper::GreaterThanOrEqual, v.into_simple_expr())
                }
                Operator::LessThan => expr.binary(BinOper::SmallerThan, v.into_simple_expr()),
                Operator::LessThanOrEqual => {
                    expr.binary(BinOper::SmallerThanOrEqual, v.into_simple_expr())
                }
                op @ (Operator::Like | Operator::NotLike) => {
                    if let Arg::Value(v) = v {
                        let v = format!(
                            "%{}%",
                            v.unwrap::<String>().replace('%', r"\%").replace('_', r"\_")
                        );
                        if op == Operator::Like {
                            expr.ilike(v)
                        } else {
                            expr.not_ilike(v)
                        }
                    } else {
                        expr.into()
                    }
                }
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

impl From<Filter> for ConditionExpression {
    fn from(f: Filter) -> Self {
        ConditionExpression::Condition(f.into_condition())
    }
}

/////////////////////////////////////////////////////////////////////////
// Arg
/////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
enum Arg {
    Value(SeaValue),
    SimpleExpr(SimpleExpr),
    Null,
}

impl IntoSimpleExpr for Arg {
    fn into_simple_expr(self) -> SimpleExpr {
        match self {
            Arg::Value(inner) => SimpleExpr::Value(inner),
            Arg::SimpleExpr(inner) => inner,
            Arg::Null => SimpleExpr::Keyword(Keyword::Null),
        }
    }
}

impl Arg {
    fn parse(s: &str, ct: &ColumnType) -> Result<Self, Error> {
        fn err(e: impl Display) -> Error {
            Error::SearchSyntax(format!(r#"conversion error: "{e}""#))
        }
        if s.eq_ignore_ascii_case("null") {
            return Ok(Arg::Null);
        }
        Ok(match ct {
            ColumnType::Uuid => Arg::Value(SeaValue::from(s.parse::<Uuid>().map_err(err)?)),
            ColumnType::Integer => Arg::Value(SeaValue::from(s.parse::<i32>().map_err(err)?)),
            ColumnType::Decimal(_) | ColumnType::Float | ColumnType::Double => {
                Arg::Value(SeaValue::from(s.parse::<f64>().map_err(err)?))
            }
            ColumnType::Enum { name, .. } => Arg::SimpleExpr(SimpleExpr::AsEnum(
                name.clone(),
                Box::new(SimpleExpr::Value(SeaValue::String(Some(Box::new(
                    s.to_owned(),
                ))))),
            )),
            ColumnType::TimestampWithTimeZone => {
                if let Ok(odt) = OffsetDateTime::parse(s, &Rfc3339) {
                    Arg::Value(SeaValue::from(odt))
                } else if let Ok(d) = Date::parse(s, &format_description!("[year]-[month]-[day]")) {
                    Arg::Value(SeaValue::from(d))
                } else if let Ok(human) = from_human_time(s) {
                    match human {
                        ParseResult::DateTime(dt) => Arg::Value(SeaValue::from(dt)),
                        ParseResult::Date(d) => Arg::Value(SeaValue::from(d)),
                        ParseResult::Time(t) => Arg::Value(SeaValue::from(t)),
                    }
                } else {
                    Arg::Value(SeaValue::from(s))
                }
            }
            _ => Arg::Value(SeaValue::from(s)),
        })
    }
}

/////////////////////////////////////////////////////////////////////////
// Operands & Operators
/////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
enum Operand {
    Simple(Expr, Arg),
    Composite(Vec<Filter>),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Operator {
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

impl Display for Operator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use Operator::*;
        match self {
            Equal => write!(f, "="),
            NotEqual => write!(f, "!="),
            Like => write!(f, "~"),
            NotLike => write!(f, "!~"),
            GreaterThan => write!(f, ">"),
            GreaterThanOrEqual => write!(f, ">="),
            LessThan => write!(f, "<"),
            LessThanOrEqual => write!(f, "<="),
            And => write!(f, "&"),
            Or => write!(f, "!"),
        }
    }
}
impl FromStr for Operator {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use Operator::*;
        match s {
            "=" => Ok(Equal),
            "!=" => Ok(NotEqual),
            "~" => Ok(Like),
            "!~" => Ok(NotLike),
            ">" => Ok(GreaterThan),
            ">=" => Ok(GreaterThanOrEqual),
            "<" => Ok(LessThan),
            "<=" => Ok(LessThanOrEqual),
            "|" => Ok(Or),
            "&" => Ok(And),
            _ => Err(Error::SearchSyntax(format!("Invalid operator: '{s}'"))),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests::*;
    use super::super::*;
    use super::*;
    use chrono::{Local, TimeDelta};
    use sea_orm::{QuerySelect, QueryTrait};
    use test_log::test;

    fn where_clause(query: &str) -> Result<String, anyhow::Error> {
        use crate::db::query::Filtering;
        use sea_orm::EntityTrait;
        Ok(advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filtering(q(query))?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string()
            .split("WHERE ")
            .last()
            .unwrap()
            .to_string())
    }

    #[test(tokio::test)]
    async fn filters() -> Result<(), anyhow::Error> {
        let columns = advisory::Entity.columns();
        let test = |s: &str, expected: Operator| match q(s).filter_for(&columns) {
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
        assert!(q("foo=bar").filter_for(&columns).is_err());

        // There aren't many bad queries since random text is
        // considered a "full-text search" in which an OR clause is
        // constructed from a LIKE clause for all string fields in the
        // entity.
        test("search the entity", Operator::Like);

        Ok(())
    }

    #[test(tokio::test)]
    async fn conditions() -> Result<(), anyhow::Error> {
        assert_eq!(
            where_clause("location=foo")?,
            r#""advisory"."location" = 'foo'"#
        );
        assert_eq!(
            where_clause(r"location=foo\=bar")?,
            r#""advisory"."location" = 'foo=bar'"#
        );
        assert_eq!(
            where_clause(r"location=foo\\bar")?,
            r#""advisory"."location" = E'foo\\bar'"#
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
        assert_eq!(
            where_clause("published=null")?,
            r#""advisory"."published" IS NULL"#
        );
        assert_eq!(
            where_clause("published!=NULL")?,
            r#""advisory"."published" IS NOT NULL"#
        );
        assert_eq!(
            where_clause("severity=high")?,
            r#""advisory"."severity" = (CAST('high' AS "Severity"))"#
        );
        assert_eq!(
            where_clause("severity>low")?,
            r#""advisory"."severity" > (CAST('low' AS "Severity"))"#
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
            where_clause(r"type\=jar")?,
            r#"("advisory"."location" ILIKE '%type=jar%') OR ("advisory"."title" ILIKE '%type=jar%')"#
        );
        assert_eq!(
            where_clause("foo&location=bar")?,
            r#"(("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%')) AND "advisory"."location" = 'bar'"#
        );
        assert_eq!(
            where_clause(r"m\&m's&location=f\&oo&id=0e840505-e29b-41d4-a716-665544004400")?,
            r#"(("advisory"."location" ILIKE E'%m&m\'s%') OR ("advisory"."title" ILIKE E'%m&m\'s%')) AND "advisory"."location" = 'f&oo' AND "advisory"."id" = '0e840505-e29b-41d4-a716-665544004400'"#
        );
        assert_eq!(
            where_clause("a|b|c")?,
            r#"("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%') OR ("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%') OR ("advisory"."location" ILIKE '%c%') OR ("advisory"."title" ILIKE '%c%')"#
        );
        assert_eq!(
            where_clause("a|b&id=0e840505-e29b-41d4-a716-665544004400")?,
            r#"(("advisory"."location" ILIKE '%a%') OR ("advisory"."title" ILIKE '%a%') OR ("advisory"."location" ILIKE '%b%') OR ("advisory"."title" ILIKE '%b%')) AND "advisory"."id" = '0e840505-e29b-41d4-a716-665544004400'"#
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
}
