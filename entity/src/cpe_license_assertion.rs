// use sea_orm::entity::prelude::*;
//
// #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
// #[sea_orm(table_name = "cpe_license_assertion")]
// pub struct Model {
//     #[sea_orm(primary_key)]
//     pub id: Uuid,
//     pub license_id: Uuid,
//     pub cpe_id: Uuid,
//     pub sbom_id: Uuid,
// }
//
// #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
// pub enum Relation {}
//
// impl ActiveModelBehavior for ActiveModel {}
