use sea_orm::{
    ColumnTrait, DbErr, EntityTrait, FromQueryResult, IntoSimpleExpr, Iterable, QueryResult,
    QuerySelect, Select, SelectModel, Selector,
};
use sea_query::{ColumnRef, SimpleExpr};

pub trait ColumnsPrefixed: Sized {
    fn try_columns_prefixed<C, I>(self, prefix: &str, cols: I) -> Result<Self, DbErr>
    where
        C: ColumnTrait,
        I: IntoIterator<Item = C>;
}

impl<T: QuerySelect> ColumnsPrefixed for T {
    fn try_columns_prefixed<C, I>(mut self, prefix: &str, cols: I) -> Result<Self, DbErr>
    where
        C: ColumnTrait,
        I: IntoIterator<Item = C>,
    {
        for col in cols.into_iter() {
            if let SimpleExpr::Column(col_ref) = col.into_simple_expr() {
                match col_ref {
                    ColumnRef::Column(name)
                    | ColumnRef::TableColumn(_, name)
                    | ColumnRef::SchemaTableColumn(_, _, name) => {
                        let mut prefixed = String::new();
                        prefixed.push_str(prefix);
                        prefixed.push_str(&name.to_string());

                        self = self.column_as(col, prefixed);
                    }
                    ColumnRef::Asterisk => {
                        return Err(DbErr::Custom("Unable to prefix asterisk".to_string()))
                    }
                    ColumnRef::TableAsterisk(_) => {
                        return Err(DbErr::Custom("Unable to prefix asterisk".to_string()))
                    }
                }
            } else {
                return Err(DbErr::Custom("Unable to prefix column".to_string()));
            }
        }
        Ok(self)
    }
}

pub trait SelectIntoMultiModel: Sized {
    fn try_model_columns<E: EntityTrait>(self, entity: E) -> Result<Self, DbErr>;

    fn try_into_multi_model<M>(self) -> Result<Selector<SelectModel<M>>, DbErr>
    where
        M: FromQueryResultMultiModel;
}

impl<E: EntityTrait> SelectIntoMultiModel for Select<E> {
    fn try_model_columns<O: EntityTrait>(self, entity: O) -> Result<Self, DbErr> {
        let name = entity.module_name();
        let prefix = format!("{name}$");
        self.try_columns_prefixed(&prefix, O::Column::iter())
    }

    fn try_into_multi_model<M>(self) -> Result<Selector<SelectModel<M>>, DbErr>
    where
        M: FromQueryResultMultiModel,
    {
        let select = M::try_into_multi_model(self)?;
        Ok(select.into_model::<M>())
    }
}

pub trait FromQueryResultMultiModel: FromQueryResult {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr>;

    fn from_query_result_multi_model<E: EntityTrait>(
        res: &QueryResult,
        entity: E,
    ) -> Result<E::Model, DbErr> {
        let name = entity.module_name();
        let prefix = format!("{name}$");
        E::Model::from_query_result(res, &prefix)
    }

    fn from_query_result_multi_model_optional<E: EntityTrait>(
        res: &QueryResult,
        entity: E,
    ) -> Result<Option<E::Model>, DbErr> {
        Ok(Self::from_query_result_multi_model(res, entity).ok())
    }
}
