use chrono::{Local, NaiveDateTime};
use human_date_parser::{from_human_time, ParseResult};
use regex::Regex;
use sea_orm::entity::ColumnDef;
use sea_orm::sea_query::{extension::postgres::PgExpr, ConditionExpression, IntoCondition};
use sea_orm::{
    sea_query, ColumnTrait, ColumnType, Condition, EntityTrait, IntoIdentity, IntoSimpleExpr,
    Iterable, Order, QueryFilter, QueryOrder, Select, Value as SeaValue,
};
use sea_query::{BinOper, ColumnRef, Expr, IntoColumnRef, Keyword, SimpleExpr};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

/// Convenience function for creating a search query
///
/// ```
/// use trustify_common::db::query::q;
///
/// let query = q("foo&bar>100").sort("bar:desc,baz");
///
/// ```
pub fn q(s: &str) -> Query {
    Query::q(s)
}

impl Query {
    /// Form expected: `{search}*{filter}*`
    ///
    /// where `{filter}` is of the form `{field}{op}{value}`
    ///
    /// Multiple searches and/or filters should be `&`-delimited
    ///
    /// The `{search}` text will result in an OR clause of LIKE clauses
    /// for every [String] field in the associated Columns. Optional
    /// filters of the form `{field}{op}{value}` may further constrain
    /// the results. Each `{field}` name must correspond to one of the
    /// selected Columns.
    ///
    /// Both `{search}` and `{value}` may contain `|`-delimited
    /// alternate values that will result in an OR clause. Any literal
    /// `|` or `&` within a search or value should be escaped with a
    /// backslash, e.g. `\|` or `\&`.
    ///
    /// `{op}` should be one of `=`, `!=`, `~`, `!~, `>=`, `>`, `<=`,
    /// or `<`.
    ///
    pub fn q(s: &str) -> Self {
        Self {
            q: s.into(),
            sort: String::default(),
        }
    }

    /// Form expected: `{sort}*`
    ///
    /// where `{sort}` is of the form `{field}[:order]` and the
    /// optional `order` should be one of `asc` or `desc`. If omitted,
    /// the order defaults to `asc`.
    ///
    /// Multiple sorts should be `,`-delimited
    ///
    /// Each `{field}` name must correspond to one of the selected
    /// Columns.
    ///
    pub fn sort(self, s: &str) -> Self {
        Self {
            q: self.q,
            sort: s.into(),
        }
    }

    /// Apply the query to a mapping of field names to values,
    /// returning true if the context is successfully matched by the
    /// query, by either a filter or a full-text search of all the
    /// values of type Value::String.
    pub fn apply(&self, context: &HashMap<&'static str, Value>) -> bool {
        use Operator::*;
        self.parse().iter().all(|c| {
            log::debug!("{c:?}");
            match c {
                Constraint {
                    field: Some(f),
                    op: Some(o),
                    value: vs,
                } => context.get(f.as_str()).is_some_and(|field| match o {
                    Equal => vs.iter().any(|v| field.eq(v)),
                    NotEqual => vs.iter().all(|v| field.ne(v)),
                    Like => vs.iter().any(|v| field.contains(v)),
                    NotLike => vs.iter().all(|v| !field.contains(v)),
                    GreaterThan => vs.iter().all(|v| field.gt(v)),
                    GreaterThanOrEqual => vs.iter().all(|v| field.ge(v)),
                    LessThan => vs.iter().all(|v| field.lt(v)),
                    LessThanOrEqual => vs.iter().all(|v| field.le(v)),
                    _ => false,
                }),
                Constraint {
                    field: None,
                    value: vs,
                    ..
                } => context
                    .values()
                    .filter(|v| matches!(v, Value::String(_)))
                    .any(|field| vs.iter().any(|v| field.contains(v))),
                _ => false,
            }
        })
    }

    fn parse(&self) -> Vec<Constraint> {
        // regex for filters: {field}{op}{value}
        const RE: &str = r"^(?<field>[[:word:]]+)(?<op>=|!=|~|!~|>=|>|<=|<)(?<value>.*)$";
        static LOCK: OnceLock<Regex> = OnceLock::new();
        #[allow(clippy::unwrap_used)]
        let regex = LOCK.get_or_init(|| (Regex::new(RE).unwrap()));

        fn encode(s: &str) -> String {
            s.replace(r"\&", "\x07").replace(r"\|", "\x08")
        }
        fn decode(s: &str) -> String {
            s.replace('\x07', "&")
                .replace('\x08', "|")
                .replace(r"\\", "\x08")
                .replace('\\', "")
                .replace('\x08', r"\")
        }
        encode(&self.q)
            .split_terminator('&')
            .map(|s| {
                if let Some(capture) = regex.captures(s) {
                    // We have a filter: {field}{op}{value}
                    let field = Some(capture["field"].into());
                    #[allow(clippy::unwrap_used)] // regex ensures we won't panic
                    let op = Some(Operator::from_str(&capture["op"]).unwrap());
                    let value = capture["value"].split('|').map(decode).collect();
                    Constraint { field, op, value }
                } else {
                    // We have a full-text search
                    Constraint {
                        field: None,
                        op: None,
                        value: s.split('|').map(decode).collect(),
                    }
                }
            })
            .collect()
    }

    fn filter_for(&self, columns: &Columns) -> Result<Filter, Error> {
        let constraints = self.parse();
        if constraints.len() == 1 {
            constraints[0].filter_for(columns)
        } else {
            let filters = constraints
                .iter()
                .map(|constraint| constraint.filter_for(columns))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Filter {
                operator: Operator::And,
                operands: Operand::Composite(filters),
            })
        }
    }
}

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

impl<T: EntityTrait> Filtering<T> for Select<T> {
    fn filtering_with<C: IntoColumns>(self, search: Query, context: C) -> Result<Self, Error> {
        let Query { q, sort, .. } = &search;
        log::debug!("filtering with: q='{q}' sort='{sort}'");
        let columns = context.columns();

        let mut result = if q.is_empty() {
            self
        } else {
            self.filter(search.filter_for(&columns)?)
        };

        if !sort.is_empty() {
            result = sort
                .split(',')
                .map(|s| Sort::parse(s, &columns))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .fold(result, |select, s| {
                    select.order_by(SimpleExpr::Column(s.field), s.order)
                });
        };

        Ok(result)
    }
}

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
pub struct Query {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub sort: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("query syntax error: {0}")]
    SearchSyntax(String),
}

/////////////////////////////////////////////////////////////////////////
// Value
/////////////////////////////////////////////////////////////////////////

pub enum Value<'a> {
    String(&'a str),
    Int(i32),
    Float(f64),
    Date(&'a OffsetDateTime),
}

impl Value<'_> {
    pub fn contains(&self, pat: &str) -> bool {
        match self {
            Self::String(s) => s.contains(pat),
            Self::Date(d) => d.to_string().contains(pat),
            _ => false,
        }
    }
}

impl PartialEq<String> for Value<'_> {
    fn eq(&self, rhs: &String) -> bool {
        match self {
            Self::String(s) => s.eq(rhs),
            Self::Int(v) => match rhs.parse::<i32>() {
                Ok(i) => v.eq(&i),
                _ => false,
            },
            Self::Float(v) => match rhs.parse::<f64>() {
                Ok(i) => v.eq(&i),
                _ => false,
            },
            Self::Date(v) => match from_human_time(&v.to_string()) {
                Ok(ParseResult::DateTime(field)) => match from_human_time(rhs) {
                    Ok(ParseResult::DateTime(other)) => field.eq(&other),
                    Ok(ParseResult::Date(d)) => {
                        let other = NaiveDateTime::new(d, field.time())
                            .and_local_timezone(Local)
                            .unwrap();
                        field.eq(&other)
                    }
                    Ok(ParseResult::Time(t)) => {
                        let other = NaiveDateTime::new(field.date_naive(), t)
                            .and_local_timezone(Local)
                            .unwrap();
                        field.eq(&other)
                    }
                    _ => false,
                },
                _ => false,
            },
        }
    }
}

impl PartialOrd<String> for Value<'_> {
    fn partial_cmp(&self, rhs: &String) -> Option<Ordering> {
        match self {
            Self::String(s) => s.partial_cmp(&rhs.as_str()),
            Self::Int(v) => match rhs.parse::<i32>() {
                Ok(i) => v.partial_cmp(&i),
                _ => None,
            },
            Self::Float(v) => match rhs.parse::<f64>() {
                Ok(i) => v.partial_cmp(&i),
                _ => None,
            },
            Self::Date(v) => match from_human_time(&v.to_string()) {
                Ok(ParseResult::DateTime(field)) => match from_human_time(rhs) {
                    Ok(ParseResult::DateTime(other)) => field.partial_cmp(&other),
                    Ok(ParseResult::Date(d)) => {
                        let other = NaiveDateTime::new(d, field.time())
                            .and_local_timezone(Local)
                            .unwrap();
                        field.partial_cmp(&other)
                    }
                    Ok(ParseResult::Time(t)) => {
                        let other = NaiveDateTime::new(field.date_naive(), t)
                            .and_local_timezone(Local)
                            .unwrap();
                        field.partial_cmp(&other)
                    }
                    _ => None,
                },
                _ => None,
            },
        }
    }
}

/////////////////////////////////////////////////////////////////////////
// Columns
/////////////////////////////////////////////////////////////////////////

/// Context of columns which can be used for filtering and sorting.
#[derive(Default, Debug, Clone)]
pub struct Columns {
    columns: Vec<(ColumnRef, ColumnDef)>,
    translator: Option<Translator>,
}

pub trait IntoColumns {
    fn columns(self) -> Columns;
}

impl IntoColumns for Columns {
    fn columns(self) -> Columns {
        self
    }
}

impl<E: EntityTrait> IntoColumns for E {
    fn columns(self) -> Columns {
        Columns::from_entity::<E>()
    }
}

pub type Translator = fn(&str, &str, &str) -> Option<String>;

impl Columns {
    /// Construct a new columns context from an entity type.
    pub fn from_entity<E: EntityTrait>() -> Self {
        let columns = E::Column::iter()
            .map(|c| {
                let (t, u) = c.as_column_ref();
                let column_ref = ColumnRef::TableColumn(t, u);
                let column_def = c.def();
                (column_ref, column_def)
            })
            .collect();
        Self {
            columns,
            translator: None,
        }
    }

    /// Add an arbitrary column into the context.
    pub fn add_column<I: IntoIdentity>(mut self, name: I, def: ColumnDef) -> Self {
        self.columns
            .push((name.into_identity().into_column_ref(), def));
        self
    }

    /// Add columns from another column context.
    ///
    /// Any columns already existing within this context will *not* be replaced
    /// by columns from the argument.
    pub fn add_columns<C: IntoColumns>(mut self, columns: C) -> Self {
        let columns = columns.columns();

        for (col_ref, col_def) in columns.columns {
            if !self
                .columns
                .iter()
                .any(|(existing_col_ref, _)| *existing_col_ref == col_ref)
            {
                self.columns.push((col_ref, col_def))
            }
        }

        self
    }

    /// Add a translator to the context
    pub fn translator(mut self, f: Translator) -> Self {
        self.translator = Some(f);
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = &(ColumnRef, ColumnDef)> {
        self.columns.iter()
    }

    /// Look up the column context for a given simple field name.
    fn for_field(&self, field: &str) -> Option<(ColumnRef, ColumnDef)> {
        self.columns
            .iter()
            .find(|(col_ref, _)| {
                matches!( col_ref,
                   ColumnRef::Column(name)
                    | ColumnRef::TableColumn(_, name)
                    | ColumnRef::SchemaTableColumn(_, _, name)
                        if name.to_string().eq_ignore_ascii_case(field))
            })
            .cloned()
    }

    fn translate(&self, field: &str, op: &str, value: &str) -> Option<String> {
        match self.translator {
            None => None,
            Some(f) => f(field, op, value),
        }
    }
}

/////////////////////////////////////////////////////////////////////////
// Filter
/////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct Filter {
    operands: Operand,
    operator: Operator,
}

// From a filter string of the form {field}{op}{value}
impl TryFrom<(&str, Operator, &Vec<String>, &Columns)> for Filter {
    type Error = Error;
    fn try_from(tuple: (&str, Operator, &Vec<String>, &Columns)) -> Result<Self, Self::Error> {
        let (ref field, operator, values, columns) = tuple;
        let (col_ref, col_def) = columns.for_field(field).ok_or(Error::SearchSyntax(format!(
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
                                operands: Operand::Simple(col_ref.clone(), v),
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
                        columns.iter().filter_map(|(col_ref, col_def)| {
                            match col_def.get_column_type() {
                                ColumnType::String(_) | ColumnType::Text => Some(Filter {
                                    operands: Operand::Simple(
                                        col_ref.clone(),
                                        Arg::Value(SeaValue::String(Some(s.clone().into()))),
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
            Operand::Simple(col, v) => match self.operator {
                Operator::Equal => match v {
                    Arg::Null => Expr::col(col).is_null(),
                    v => Expr::col(col).binary(BinOper::Equal, v.into_simple_expr()),
                },
                Operator::NotEqual => match v {
                    Arg::Null => Expr::col(col).is_not_null(),
                    v => Expr::col(col).binary(BinOper::NotEqual, v.into_simple_expr()),
                },
                Operator::GreaterThan => {
                    Expr::col(col).binary(BinOper::GreaterThan, v.into_simple_expr())
                }
                Operator::GreaterThanOrEqual => {
                    Expr::col(col).binary(BinOper::GreaterThanOrEqual, v.into_simple_expr())
                }
                Operator::LessThan => {
                    Expr::col(col).binary(BinOper::SmallerThan, v.into_simple_expr())
                }
                Operator::LessThanOrEqual => {
                    Expr::col(col).binary(BinOper::SmallerThanOrEqual, v.into_simple_expr())
                }
                op @ (Operator::Like | Operator::NotLike) => {
                    if let Arg::Value(v) = v {
                        let v = format!(
                            "%{}%",
                            v.unwrap::<String>().replace('%', r"\%").replace('_', r"\_")
                        );
                        if op == Operator::Like {
                            SimpleExpr::Column(col).ilike(v)
                        } else {
                            SimpleExpr::Column(col).not_ilike(v)
                        }
                    } else {
                        SimpleExpr::Column(col)
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
// Sort
/////////////////////////////////////////////////////////////////////////

struct Sort {
    field: ColumnRef,
    order: Order,
}

impl Sort {
    fn parse(s: &str, columns: &Columns) -> Result<Self, Error> {
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
// Constraint
/////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct Constraint {
    field: Option<String>, // None for full-text searches
    op: Option<Operator>,  // None for full-text searches
    value: Vec<String>,    // to account for '|'-delimited values
}

impl Constraint {
    fn filter_for(&self, columns: &Columns) -> Result<Filter, Error> {
        match (&self.field, self.op) {
            // We have a filter of the form, {field}{op}{value}
            (Some(field), Some(operator)) => {
                Filter::try_from((field.as_str(), operator, &self.value, columns))
            }
            // We have a full-text search query
            (None, _) => Filter::try_from((&self.value, columns)),
            _ => Err(Error::SearchSyntax(format!("Invalid query: '{self:?}'"))),
        }
    }
}

/////////////////////////////////////////////////////////////////////////
// Operands & Operators
/////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
enum Operand {
    Simple(ColumnRef, Arg),
    Composite(Vec<Filter>),
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

/////////////////////////////////////////////////////////////////////////
// Tests
/////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeDelta};
    use sea_orm::{ColumnTypeTrait, QuerySelect, QueryTrait};
    use sea_query::{Func, StringLen};
    use test_log::test;

    #[test(tokio::test)]
    async fn happy_path() -> Result<(), anyhow::Error> {
        let stmt = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filtering(q("foo&published>2024-04-20").sort("location,title:desc"))?
            .order_by_desc(advisory::Column::Id)
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();
        assert_eq!(
            stmt,
            r#"SELECT "advisory"."id" FROM "advisory" WHERE (("advisory"."location" ILIKE '%foo%') OR ("advisory"."title" ILIKE '%foo%')) AND "advisory"."published" > '2024-04-20' ORDER BY "advisory"."location" ASC, "advisory"."title" DESC, "advisory"."id" DESC"#
        );
        Ok(())
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
    async fn filters_extra_columns() -> Result<(), anyhow::Error> {
        let test = |s: &str, expected: Operator| {
            let columns = advisory::Entity
                .columns()
                .add_column("len", ColumnType::Integer.def());
            match q(s).filter_for(&columns) {
                Ok(Filter {
                    operands: Operand::Composite(v),
                    ..
                }) => assert_eq!(
                    v[0].operator, expected,
                    "The query '{s}' didn't resolve to {expected:?}"
                ),
                _ => panic!("The query '{s}' didn't resolve to {expected:?}"),
            }
        };

        test("len=42", Operator::Equal);
        test("len!=42", Operator::NotEqual);
        test("len~42", Operator::Like);
        test("len!~42", Operator::NotLike);
        test("len>42", Operator::GreaterThan);
        test("len>=42", Operator::GreaterThanOrEqual);
        test("len<42", Operator::LessThan);
        test("len<=42", Operator::LessThanOrEqual);

        Ok(())
    }

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

    #[test(tokio::test)]
    async fn conditions_on_extra_columns() -> Result<(), anyhow::Error> {
        let query = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .expr_as_(
                Func::char_length(Expr::col("location".into_identity())),
                "location_len",
            );

        let sql = query
            .filtering_with(
                q("location_len>10"),
                advisory::Entity
                    .columns()
                    .add_column("location_len", ColumnType::Integer.def()),
            )?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string();

        assert_eq!(
            sql,
            r#"SELECT "advisory"."id", CHAR_LENGTH("location") AS "location_len" FROM "advisory" WHERE "location_len" > 10"#
        );

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

    #[test(tokio::test)]
    async fn translation() -> Result<(), anyhow::Error> {
        let test = |query: Query, expected: &str| {
            let stmt = advisory::Entity::find()
                .select_only()
                .column(advisory::Column::Id)
                .filtering_with(
                    query,
                    advisory::Entity.columns().translator(|f, op, v| {
                        match (f, op, v) {
                            ("severity", "=", "low") => Some("score>=0&score<3"),
                            ("severity", "=", "medium") => Some("score>=3&score<6"),
                            ("severity", "=", "high") => Some("score>=6&score<10"),
                            ("severity", ">", "low") => Some("score>3"),
                            ("severity", ">", "medium") => Some("score>6"),
                            ("severity", ">", "high") => Some("score>10"),
                            ("severity", "<", "low") => Some("score<0"),
                            ("severity", "<", "medium") => Some("score<3"),
                            ("severity", "<", "high") => Some("score<6"),
                            _ => None,
                        }
                        .map(String::from)
                        .or_else(|| match (f, v) {
                            ("severity", "") => Some(format!("score:{op}")),
                            _ => None,
                        })
                    }),
                )
                .unwrap()
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE")
                .last()
                .expect("problem splitting string")
                .trim()
                .to_string();
            assert_eq!(stmt, expected);
        };

        test(
            q("severity>medium").sort("severity:desc"),
            r#""advisory"."score" > 6 ORDER BY "advisory"."score" DESC"#,
        );
        test(
            q("severity=medium"),
            r#""advisory"."score" >= 3 AND "advisory"."score" < 6"#,
        );
        test(
            q("severity=low|high"),
            r#"("advisory"."score" >= 0 AND "advisory"."score" < 3) OR ("advisory"."score" >= 6 AND "advisory"."score" < 10)"#,
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn apply_to_context() -> Result<(), anyhow::Error> {
        use time::format_description::well_known::Rfc2822;
        let now = time::OffsetDateTime::now_utc();
        let then = OffsetDateTime::parse("Sat, 12 Jun 1993 13:25:19 GMT", &Rfc2822)?;
        let context = HashMap::from([
            ("id", Value::String("foo")),
            ("count", Value::Int(42)),
            ("score", Value::Float(6.66)),
            ("detected", Value::Date(&then)),
            ("published", Value::Date(&now)),
        ]);
        assert!(q("oo|aa|bb&count<100&count>10&id=foo").apply(&context));
        assert!(q("score=6.66").apply(&context));
        assert!(q("count>=42&count<=42").apply(&context));
        assert!(q("published>2 days ago&published<next week").apply(&context));

        assert!(q("detected=1993-06-12").apply(&context));
        assert!(q("detected>13:20:00").apply(&context));
        assert!(q("detected~1993").apply(&context));
        assert!(!q("1993").apply(&context));

        assert!(q(&format!("published={}", now)).apply(&context));
        assert!(q(&format!("published={}", now.date())).apply(&context));
        assert!(q(&format!("published={}", now.time())).apply(&context));
        assert!(q(&format!("published>=today {}", now.time())).apply(&context));
        assert!(q(&format!("published>={}", now)).apply(&context));
        assert!(q(&format!("published<={}", now.date())).apply(&context));
        assert!(q(&format!("published~{}", now.time())).apply(&context));

        Ok(())
    }

    /////////////////////////////////////////////////////////////////////////
    // Test helpers
    /////////////////////////////////////////////////////////////////////////

    fn where_clause(query: &str) -> Result<String, anyhow::Error> {
        Ok(advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filtering(q(query))?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string()
            .split("WHERE")
            .last()
            .expect("problem splitting string")
            .trim()
            .to_string())
    }

    mod advisory {
        use sea_orm::entity::prelude::*;
        use time::OffsetDateTime;

        #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
        #[sea_orm(table_name = "advisory")]
        pub struct Model {
            #[sea_orm(primary_key)]
            pub id: Uuid,
            pub location: String,
            pub title: String,
            pub published: Option<OffsetDateTime>,
            pub severity: Severity,
            pub score: f64,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}

        #[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
        #[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "severity")]
        pub enum Severity {
            #[sea_orm(string_value = "low")]
            Low,
            #[sea_orm(string_value = "medium")]
            Medium,
            #[sea_orm(string_value = "high")]
            High,
        }
    }
}
