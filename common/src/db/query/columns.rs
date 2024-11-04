use std::fmt::{Display, Formatter};

use sea_orm::entity::ColumnDef;
use sea_orm::{sea_query, ColumnTrait, ColumnType, EntityTrait, IntoIdentity, Iterable};
use sea_query::{Alias, ColumnRef, IntoColumnRef, IntoIden};

/// Context of columns which can be used for filtering and sorting.
#[derive(Default, Debug, Clone)]
pub struct Columns {
    columns: Vec<(ColumnRef, ColumnDef)>,
    translator: Option<Translator>,
}

impl Display for Columns {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (r, d) in &self.columns {
            writeln!(f)?;
            match r {
                ColumnRef::SchemaTableColumn(_, t, c) | ColumnRef::TableColumn(t, c) => {
                    write!(f, "  \"{}\".\"{}\"", t.to_string(), c.to_string())?
                }
                ColumnRef::Column(c) => write!(f, "  \"{}\"", c.to_string())?,
                _ => write!(f, "  {r:?}")?,
            }
            write!(f, " : ")?;
            match d.get_column_type() {
                ColumnType::Text | ColumnType::String(_) | ColumnType::Char(_) => {
                    write!(f, "String")?
                }
                ColumnType::Enum {
                    name: _,
                    variants: v,
                } => write!(
                    f,
                    "Enum {:?}",
                    v.iter().map(|v| v.to_string()).collect::<Vec<_>>()
                )?,
                t => write!(f, "  {t:?}")?,
            }
        }
        Ok(())
    }
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

    /// Alias a table name
    pub fn alias(mut self, from: &str, to: &str) -> Self {
        self.columns = self
            .columns
            .into_iter()
            .map(|(r, d)| match r {
                ColumnRef::TableColumn(t, c) if t.to_string().eq_ignore_ascii_case(from) => {
                    (ColumnRef::TableColumn(Alias::new(to).into_iden(), c), d)
                }
                _ => (r, d),
            })
            .collect();
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = &(ColumnRef, ColumnDef)> {
        self.columns.iter()
    }

    /// Look up the column context for a given simple field name.
    pub(crate) fn for_field(&self, field: &str) -> Option<(ColumnRef, ColumnDef)> {
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

    pub(crate) fn translate(&self, field: &str, op: &str, value: &str) -> Option<String> {
        match self.translator {
            None => None,
            Some(f) => f(field, op, value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::super::*;
    use super::*;
    use sea_orm::{ColumnType, ColumnTypeTrait, QuerySelect, QueryTrait};
    use sea_query::{Expr, Func};
    use test_log::test;

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
    async fn filters_extra_columns() -> Result<(), anyhow::Error> {
        let test = |s: &str, expected: &str, def: ColumnDef| {
            let stmt = advisory::Entity::find()
                .select_only()
                .column(advisory::Column::Id)
                .filtering_with(q(s), advisory::Entity.columns().add_column("len", def))
                .unwrap()
                .build(sea_orm::DatabaseBackend::Postgres)
                .to_string()
                .split("WHERE ")
                .last()
                .unwrap()
                .to_string();
            assert_eq!(stmt, expected);
        };

        use ColumnType::*;
        test("len=42", r#""len" = 42"#, Integer.def());
        test("len!=42", r#""len" <> 42"#, Integer.def());
        test("len~42", r#""len" ILIKE '%42%'"#, Text.def());
        test("len!~42", r#""len" NOT ILIKE '%42%'"#, Text.def());
        test("len>42", r#""len" > 42"#, Integer.def());
        test("len>=42", r#""len" >= 42"#, Integer.def());
        test("len<42", r#""len" < 42"#, Integer.def());
        test("len<=42", r#""len" <= 42"#, Integer.def());

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
                .split("WHERE ")
                .last()
                .unwrap()
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
    async fn table_aliasing() -> Result<(), anyhow::Error> {
        let clause = advisory::Entity::find()
            .select_only()
            .column(advisory::Column::Id)
            .filtering_with(
                q("location=here"),
                advisory::Entity.columns().alias("advisory", "foo"),
            )?
            .build(sea_orm::DatabaseBackend::Postgres)
            .to_string()
            .split("WHERE ")
            .last()
            .unwrap()
            .to_string();

        assert_eq!(clause, r#""foo"."location" = 'here'"#);

        Ok(())
    }
}
