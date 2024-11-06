use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserPreferences::Table)
                    .col(
                        ColumnDef::new(UserPreferences::UserId)
                            .string()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(UserPreferences::Key)
                            .string()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(UserPreferences::Revision)
                            .uuid()
                            .not_null()
                            .to_owned(),
                    )
                    .col(
                        ColumnDef::new(UserPreferences::Data)
                            .json_binary()
                            .not_null()
                            .to_owned(),
                    )
                    .primary_key(
                        Index::create()
                            .col(UserPreferences::UserId)
                            .col(UserPreferences::Key),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserPreferences::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum UserPreferences {
    Table,
    UserId,
    Key,
    Revision,
    Data,
}
