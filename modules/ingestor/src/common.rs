use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Related, Select};
use trustify_entity::advisory;
use utoipa::ToSchema;

#[derive(
    Copy, Clone, PartialEq, Eq, Debug, Default, ToSchema, serde::Deserialize, serde::Serialize,
)]
pub enum Deprecation {
    /// Ignore deprecated documents
    #[default]
    Ignore,
    /// Consider deprecated documents
    Consider,
}

impl Deprecation {
    pub fn filter(&self, advisories: Select<advisory::Entity>) -> Select<advisory::Entity> {
        // rule out deprecated advisories, if requested to
        match self {
            Deprecation::Ignore => advisories.filter(advisory::Column::Deprecated.eq(false)),
            Deprecation::Consider => advisories,
        }
    }

    pub fn filter_for<E>(&self, other: Select<E>) -> Select<E>
    where
        E: EntityTrait + Related<advisory::Entity>,
    {
        match self {
            Deprecation::Ignore => other
                .left_join(advisory::Entity)
                .filter(advisory::Column::Deprecated.eq(false)),
            Deprecation::Consider => other,
        }
    }
}

/// Extend advisory queries with deprecation.
pub trait DeprecationExt {
    /// Apply deprecation filtering to e.g. [`Select`].
    fn with_deprecation(self, deprecation: Deprecation) -> Self;
}

impl DeprecationExt for Select<advisory::Entity> {
    fn with_deprecation(self, deprecation: Deprecation) -> Self {
        deprecation.filter(self)
    }
}

/// Extend queries relating to advisories with deprecation.
pub trait DeprecationForExt {
    /// Apply deprecation filtering to e.g. [`Select`] which has a relation to [`advisory::Entity`].
    fn with_deprecation_related(self, deprecation: Deprecation) -> Self;
}

impl<E> DeprecationForExt for Select<E>
where
    E: EntityTrait + Related<advisory::Entity>,
{
    fn with_deprecation_related(self, deprecation: Deprecation) -> Self {
        deprecation.filter_for(self)
    }
}
