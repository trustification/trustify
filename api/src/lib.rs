mod system;

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use sea_orm_migration::MigratorTrait;

use migration::Migrator;




#[cfg(test)]
mod tests {
    use crate::system::System;
    use super::*;

    #[tokio::test]
    async fn ingest_packages() -> Result<(), anyhow::Error> {
        let system = System::start().await?;

        let packages = [
            "pkg:maven/io.quarkus/quarkus-hibernate-orm@2.13.5.Final?type=jar",
            "pkg:maven/io.quarkus/quarkus-core@2.13.5.Final?type=jar",
            "pkg:maven/jakarta.el/jakarta.el-api@3.0.3?type=jar",
            "pkg:maven/org.postgresql/postgresql@42.5.0?type=jar",
            "pkg:maven/io.quarkus/quarkus-narayana-jta@2.13.5.Final?type=jar",
            "pkg:maven/jakarta.interceptor/jakarta.interceptor-api@1.2.5?type=jar",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1?type=jar",
            "pkg:maven/io.quarkus/quarkus-jdbc-postgresql@2.13.5.Final?type=jar",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=war",
            "pkg:maven/jakarta.enterprise/jakarta.enterprise.cdi-api@2.0.2?type=jar&cheese=cheddar",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.3",
        ];

        for pkg in packages {
            system.ingest_package( pkg ).await?;
        }

        let package_types = system.package_types().await?;
        println!("{:#?}", package_types);

        let package_namespaces = system.package_namespaces().await?;
        println!("{:#?}", package_namespaces);

        let package_names = system.package_names().await?;
        println!("{:#?}", package_names);

        let packages = system.packages().await?;

        for pkg in packages {
            println!("{}", pkg.to_string());
        }

        Ok(())
    }

}
