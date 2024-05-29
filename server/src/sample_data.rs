use std::time::Duration;
use trustify_common::config::Database;
use trustify_module_importer::model::{
    CommonImporter, CsafImporter, ImporterConfiguration, OsvImporter, SbomImporter,
};
use trustify_module_importer::service::{Error, ImporterService};
use url::Url;

async fn add(
    importer: &ImporterService,
    name: &str,
    config: ImporterConfiguration,
) -> anyhow::Result<()> {
    Ok(importer
        .create(name.into(), config)
        .await
        .or_else(|err| match err {
            Error::AlreadyExists(_) => Ok(()),
            err => Err(err),
        })?)
}

async fn add_osv(
    importer: &ImporterService,
    name: &str,
    source: &str,
    base: Option<&str>,
    description: &str,
) -> anyhow::Result<()> {
    add(
        importer,
        name,
        ImporterConfiguration::Osv(OsvImporter {
            common: CommonImporter {
                disabled: true,
                period: Duration::from_secs(300),
                description: Some(description.into()),
            },
            source: source.to_string(),
            path: base.map(|s| s.into()),
        }),
    )
    .await
}

pub async fn sample_data(db: trustify_common::db::Database) -> anyhow::Result<()> {
    let importer = ImporterService::new(db);

    add(&importer, "redhat-sbom",  ImporterConfiguration::Sbom(SbomImporter {
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
    })).await?;

    add(
        &importer,
        "redhat-csaf-vex-2024",
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
    .await?;

    add_osv(
        &importer,
        "osv-pypa",
        "https://github.com/pypa/advisory-database",
        Some("vulns"),
        "Python Packaging Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-psf",
        "https://github.com/psf/advisory-database",
        Some("advisories"),
        "Python Software Foundation Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-r",
        "https://github.com/RConsortium/r-advisory-database",
        Some("vulns"),
        "RConsortium Advisory Database",
    )
    .await?;

    add_osv(
        &importer,
        "osv-oss-fuzz",
        "https://github.com/google/oss-fuzz-vulns",
        Some("vulns"),
        "OSS-Fuzz vulnerabilities",
    )
    .await?;

    Ok(())
}
