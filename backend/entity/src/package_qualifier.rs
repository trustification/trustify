use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "package_qualifier")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub qualified_package_id: i32,
    pub key: String,
    pub value: String,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::qualified_package::Entity",
        from = "super::package_qualifier::Column::QualifiedPackageId"
        to = "super::qualified_package::Column::Id")]
    QualifiedPackage,
}

impl Related<super::qualified_package::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::QualifiedPackage.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
