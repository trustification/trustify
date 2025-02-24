use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(SbomNodeChecksum::Table)
                    .col(ColumnDef::new(SbomNodeChecksum::SbomId).uuid().not_null())
                    .col(ColumnDef::new(SbomNodeChecksum::NodeId).string().not_null())
                    .col(ColumnDef::new(SbomNodeChecksum::Type).uuid().not_null())
                    .col(ColumnDef::new(SbomNodeChecksum::Value).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SbomNodeChecksum::Table,
                                (SbomNodeChecksum::SbomId, SbomNodeChecksum::NodeId),
                            )
                            .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomNodeChecksum::SbomId)
                            .col(SbomNodeChecksum::NodeId)
                            .col(SbomNodeChecksum::Type)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(SbomNodeChecksum::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SbomNodeChecksum {
    Table,

    SbomId,
    NodeId,
    Type,
    Value,
}

#[derive(DeriveIden)]
enum SbomNode {
    Table,

    SbomId,
    NodeId,
}
