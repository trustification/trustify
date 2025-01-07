use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Conversation::Table)
                    .col(
                        ColumnDef::new(Conversation::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Conversation::UserId).string().not_null())
                    .col(ColumnDef::new(Conversation::State).json_binary().not_null())
                    .col(ColumnDef::new(Conversation::Seq).integer().not_null())
                    .col(ColumnDef::new(Conversation::Summary).string().not_null())
                    .col(
                        ColumnDef::new(Conversation::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // this index should speed up lookup up the most recent conversations for a user
        manager
            .create_index(
                Index::create()
                    .table(Conversation::Table)
                    .name(Indexes::ConversationUserIdUpdatedAtIdx.to_string())
                    .col(Conversation::UserId)
                    .col(Conversation::UpdatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Conversation::Table)
                    .name(Indexes::ConversationUserIdUpdatedAtIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(Conversation::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Indexes {
    ConversationUserIdUpdatedAtIdx,
}

#[derive(DeriveIden)]
enum Conversation {
    Table,
    Id,
    UserId,
    State,
    Seq,
    Summary,
    UpdatedAt,
}
