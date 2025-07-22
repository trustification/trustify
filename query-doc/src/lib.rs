use std::marker::PhantomData;
use utoipa::{
    IntoParams,
    openapi::{
        ObjectBuilder, Type,
        path::{Parameter, ParameterIn},
    },
};

pub trait QueryDoc {
    fn generate_query_doc() -> String;
    fn generate_sort_doc() -> String;
}

pub struct TrustifyQuery<T: QueryDoc> {
    phantom: PhantomData<T>,
}

impl<T: QueryDoc> IntoParams for TrustifyQuery<T> {
    fn into_params(_parameter_in_provider: impl Fn() -> Option<ParameterIn>) -> Vec<Parameter> {
        vec![
            utoipa::openapi::path::ParameterBuilder::new()
                .name("q")
                .parameter_in(ParameterIn::Query)
                .description(Some(T::generate_query_doc()))
                .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                .build(),
            utoipa::openapi::path::ParameterBuilder::new()
                .name("sort")
                .parameter_in(ParameterIn::Query)
                .description(Some(T::generate_sort_doc()))
                .schema(Some(ObjectBuilder::new().schema_type(Type::String)))
                .build(),
        ]
    }
}
