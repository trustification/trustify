use std::time::Duration;
use trustify_common::config::Database;
use trustify_module_importer::model::{
    CommonImporter, CsafImporter, ImporterConfiguration, SbomImporter,
};
use trustify_module_importer::service::{Error, ImporterService};
use url::Url;

pub async fn sample_data(db: &Database) -> anyhow::Result<()> {
    let db = trustify_common::db::Database::new(db).await?;

    let importer = ImporterService::new(db);
    importer
        .create(
            "redhat-sbom".into(),
            ImporterConfiguration::Sbom(SbomImporter {
                common: CommonImporter {
                    disabled: true,
                    period: Duration::from_secs(300),
                    description: Some("All Red Hat SBOMs".into())
                },
                source: "https://access.redhat.com/security/data/sbom/beta/".to_string(),
                keys: vec![
                    Url::parse("https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4")?
                ],
                v3_signatures: true,
                only_patterns: vec![],
            }),
        )
        .await.or_else(|err|match err {
            Error::AlreadyExists(_) =>Ok(()),
            err => Err(err)
        })?;
    importer
        .create(
            "redhat-csaf-vex-2024".into(),
            ImporterConfiguration::Csaf(CsafImporter {
                common: CommonImporter {
                    disabled: true,
                    period: Duration::from_secs(300),
                    description: Some("Red Hat VEX files from 2024".into()),
                },
                source: "redhat.com".to_string(),
                v3_signatures: true,
                only_patterns: vec!["^cve-2024-".into()],
            }),
        )
        .await
        .or_else(|err| match err {
            Error::AlreadyExists(_) => Ok(()),
            err => Err(err),
        })?;

    Ok(())
}
