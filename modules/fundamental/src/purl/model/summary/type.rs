use crate::purl::model::TypeHead;
use crate::Error;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DeriveColumn, EntityTrait, EnumIter, QueryFilter, QuerySelect,
};
use serde::{Deserialize, Serialize};
use trustify_entity::{base_purl, qualified_purl, versioned_purl};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct TypeSummary {
    #[serde(flatten)]
    pub head: TypeHead,
    pub counts: TypeCounts,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct TypeCounts {
    pub base: i64,
    pub version: i64,
    pub package: i64,
}

impl TypeSummary {
    pub async fn from_names<C: ConnectionTrait>(
        names: &Vec<String>,
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        #[derive(Copy, Clone, Debug, EnumIter, DeriveColumn)]
        enum QueryAs {
            Count,
        }

        let mut summaries = Vec::new();

        for name in names {
            let base: Option<i64> = base_purl::Entity::find()
                .filter(base_purl::Column::Type.eq(name))
                .select_only()
                .column_as(base_purl::Column::Id.count(), "count")
                .into_values::<_, QueryAs>()
                .one(tx)
                .await?;

            let version: Option<i64> = versioned_purl::Entity::find()
                .left_join(base_purl::Entity)
                .filter(base_purl::Column::Type.eq(name))
                .select_only()
                .column_as(versioned_purl::Column::Id.count(), "count")
                .into_values::<_, QueryAs>()
                .one(tx)
                .await?;

            let package: Option<i64> = qualified_purl::Entity::find()
                .left_join(versioned_purl::Entity)
                .left_join(base_purl::Entity)
                .filter(base_purl::Column::Type.eq(name))
                .select_only()
                .column_as(versioned_purl::Column::Id.count(), "count")
                .into_values::<_, QueryAs>()
                .one(tx)
                .await?;

            summaries.push(TypeSummary {
                head: TypeHead { name: name.clone() },
                counts: TypeCounts {
                    base: base.unwrap_or_default(),
                    version: version.unwrap_or_default(),
                    package: package.unwrap_or_default(),
                },
            })
        }

        Ok(summaries)
    }
}
