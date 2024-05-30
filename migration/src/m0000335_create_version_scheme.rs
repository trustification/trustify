use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(VersionScheme::Table)
                    .col(ColumnDef::new(VersionScheme::Id).string().primary_key())
                    .col(ColumnDef::new(VersionScheme::Name).string().not_null())
                    .col(ColumnDef::new(VersionScheme::Description).string())
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();

        insert(
            db,
            "semver",
            "Semantic Versioning",
            Some("Semantic versioning as defined by SemVer 2.0.0 (see https://semver.org/)"),
        )
        .await?;

        insert(
            db,
            "ecosystem",
            "Ecosystem-specific",
            Some("Ecosystem-specific versioning; otherwise unspecified"),
        )
        .await?;

        insert(
            db,
            "git",
            "Git commit-hash",
            Some("Git commit-hash-based versioning"),
        )
        .await?;

        // package-url `vers` variants
        //
        // https://github.com/package-url/purl-spec/blob/version-range-spec/VERSION-RANGE-SPEC.rst

        insert(
            db,
            "deb",
            "Debian and Ubuntu",
            Some("https://www.debian.org/doc/debian-policy/ch-relationships.html"),
        )
        .await?;

        insert(
            db,
            "rpm",
            "RPM distributions",
            Some("https://rpm-software-management.github.io/rpm/manual/dependencies.html"),
        )
        .await?;

        insert(
            db,
            "gem",
            "Rubygems",
            Some("https://guides.rubygems.org/patterns/#semantic-versioning"),
        )
        .await?;

        insert(
            db,
            "npm",
            "NPM",
            Some("https://github.com/npm/node-semver#ranges"),
        )
        .await?;

        insert(
            db,
            "pypi",
            "Python",
            Some("https://www.python.org/dev/peps/pep-0440/"),
        )
        .await?;

        insert(
            db,
            "cpan",
            "Perl",
            Some(
                "https://perlmaven.com/how-to-compare-version-numbers-in-perl-and-for-cpan-modules",
            ),
        )
        .await?;

        insert(
            db,
            "golang",
            "Go modules",
            Some("https://golang.org/ref/mod#versions"),
        )
        .await?;

        insert(
            db,
            "maven",
            "Apache Maven",
            Some("http://maven.apache.org/enforcer/enforcer-rules/versionRanges.html"),
        )
        .await?;

        insert(
            db,
            "nuget",
            "NuGet",
            Some(
                "https://docs.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges",
            ),
        )
        .await?;

        insert(
            db,
            "gentoo",
            "Gentoo",
            Some("https://wiki.gentoo.org/wiki/Version_specifier"),
        )
        .await?;

        insert(
            db,
            "alpine",
            "Alpine Linux",
            Some("https://gitlab.alpinelinux.org/alpine/apk-tools/-/blob/master/src/version.c"),
        )
        .await?;

        insert(db, "generic", "Generic", None).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(VersionScheme::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

async fn insert(
    db: &SchemaManagerConnection<'_>,
    id: &str,
    name: &str,
    description: Option<&str>,
) -> Result<(), DbErr> {
    db.execute(
        db.get_database_backend().build(
            Query::insert()
                .into_table(VersionScheme::Table)
                .columns([
                    VersionScheme::Id,
                    VersionScheme::Name,
                    VersionScheme::Description,
                ])
                .values([
                    SimpleExpr::Value(Value::String(Some(Box::new(id.to_string())))),
                    SimpleExpr::Value(Value::String(Some(Box::new(name.to_string())))),
                    SimpleExpr::Value(Value::String(description.map(|e| Box::new(e.to_string())))),
                ])
                .map_err(|e| DbErr::Custom(e.to_string()))?,
        ),
    )
    .await?;
    Ok(())
}

#[derive(DeriveIden)]
enum VersionScheme {
    Table,
    Id,
    Name,
    Description,
}
