use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomExternalNode::Table)
                    .add_column(ColumnDef::new(SbomExternalNode::DiscriminatorType).integer())
                    .add_column(ColumnDef::new(SbomExternalNode::DiscriminatorValue).string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SbomExternalNode::Table)
                    .drop_column(SbomExternalNode::DiscriminatorType)
                    .drop_column(SbomExternalNode::DiscriminatorValue)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SbomExternalNode {
    Table,
    DiscriminatorType,
    DiscriminatorValue,
}
