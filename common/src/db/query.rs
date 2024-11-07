mod columns;
mod filter;
mod filtering;
mod sort;
mod value;

pub use columns::{Columns, IntoColumns};
pub use filtering::Filtering;
pub use value::Value;

use filter::{Filter, Operator};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sort::Sort;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::OnceLock;
use utoipa::{IntoParams, ToSchema};

/// Convenience function for creating a search Query
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
        self.parse().iter().all(|c| match c {
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
        Ok(match constraints.len() {
            1 => constraints[0].filter_for(columns)?,
            _ => Filter::all(
                constraints
                    .iter()
                    .map(|constraint| constraint.filter_for(columns))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        })
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub sort: String,
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("query syntax error: {0}")]
    SearchSyntax(String),
}

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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sea_orm::{EntityTrait, QueryOrder, QuerySelect, QueryTrait};
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

    /////////////////////////////////////////////////////////////////////////
    // Dummy Entity used for multiple tests in the crate
    /////////////////////////////////////////////////////////////////////////

    pub(crate) mod advisory {
        use std::collections::HashMap;

        use sea_orm::{entity::prelude::*, FromJsonQueryResult};
        use serde::{Deserialize, Serialize};
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
            #[sea_orm(column_type = "JsonBinary")]
            pub purl: CanonicalPurl,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}

        #[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
        #[sea_orm(rs_type = "String", db_type = "Enum")]
        pub enum Severity {
            #[sea_orm(string_value = "low")]
            Low,
            #[sea_orm(string_value = "medium")]
            Medium,
            #[sea_orm(string_value = "high")]
            High,
        }

        #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, FromJsonQueryResult)]
        pub struct CanonicalPurl(pub HashMap<String, String>);
    }
}
