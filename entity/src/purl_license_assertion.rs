// use sea_orm::entity::prelude::*;
//
// #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
// #[sea_orm(table_name = "purl_license_assertion")]
// pub struct Model {
//     #[sea_orm(primary_key)]
//     pub id: Uuid,
//     pub license_id: Uuid,
//     pub versioned_purl_id: Uuid,
//     pub sbom_id: Uuid,
// }
//
// #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
// pub enum Relation {
//     #[sea_orm(belongs_to="super::versioned_purl::Entity"
//         from = "Column::VersionedPurlId",
//         to = "super::versioned_purl::Column::Id",
//     )]
//     VersionedPurl,
//
//     #[sea_orm(belongs_to="super::license::Entity"
//         from = "Column::LicenseId",
//         to = "super::license::Column::Id",
//     )]
//     License,
//
//     #[sea_orm(belongs_to="super::sbom::Entity"
//         from = "Column::SbomId",
//         to = "super::sbom::Column::SbomId",
//     )]
//     Sbom,
// }
//
// impl Related<super::versioned_purl::Entity> for Entity {
//     fn to() -> RelationDef {
//         Relation::VersionedPurl.def()
//     }
// }
//
// impl Related<super::license::Entity> for Entity {
//     fn to() -> RelationDef {
//         Relation::License.def()
//     }
// }
//
// impl Related<super::sbom::Entity> for Entity {
//     fn to() -> RelationDef {
//         Relation::Sbom.def()
//     }
// }
//
// impl ActiveModelBehavior for ActiveModel {}
