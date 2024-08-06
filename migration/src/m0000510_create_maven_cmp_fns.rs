use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let x = manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000510_create_maven_cmp_fns/mavenver_cmp.sql"
            ))
            .await
            .map(|_| ());

        println!("{:#?}", x);

        x?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000510_create_maven_cmp_fns/maven_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000510_create_maven_cmp_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("drop function mavenver_cmp")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function maven_version_matches")
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000485_create_gitver_cmp_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }
}
