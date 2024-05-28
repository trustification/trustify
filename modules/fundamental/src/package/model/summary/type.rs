use crate::package::model::TypeHead;
use crate::Error;
use sea_orm::{ColumnTrait, DeriveColumn, EntityTrait, EnumIter, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{package, package_version, qualified_package};
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
    pub async fn from_names(
        names: &Vec<String>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        #[derive(Copy, Clone, Debug, EnumIter, DeriveColumn)]
        enum QueryAs {
            Count,
        }

        let mut summaries = Vec::new();

        for name in names {
            let base: Option<i64> = package::Entity::find()
                .filter(package::Column::Type.eq(name))
                .select_only()
                .column_as(package::Column::Id.count(), "count")
                .into_values::<_, QueryAs>()
                .one(tx)
                .await?;

            let version: Option<i64> = package_version::Entity::find()
                .left_join(package::Entity)
                .filter(package::Column::Type.eq(name))
                .select_only()
                .column_as(package_version::Column::Id.count(), "count")
                .into_values::<_, QueryAs>()
                .one(tx)
                .await?;

            let package: Option<i64> = qualified_package::Entity::find()
                .left_join(package_version::Entity)
                .left_join(package::Entity)
                .filter(package::Column::Type.eq(name))
                .select_only()
                .column_as(package_version::Column::Id.count(), "count")
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
