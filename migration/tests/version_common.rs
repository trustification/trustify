use migration::sea_orm::Statement;
use migration::ConnectionTrait;
use trustify_common::db::Database;

#[allow(unused)]
pub enum VersionRange {
    Exact(&'static str),
    Range(Version, Version),
}

#[allow(unused)]
pub enum Version {
    Inclusive(&'static str),
    Exclusive(&'static str),
    Unbounded,
}

#[allow(unused)]
pub async fn version_matches(
    db: &Database,
    candidate: &str,
    range: VersionRange,
    version_scheme: &str,
) -> Result<bool, anyhow::Error> {
    let (low, low_inclusive, high, high_inclusive) = match range {
        VersionRange::Exact(version) => (
            Some(version.to_string()),
            true,
            Some(version.to_string()),
            true,
        ),
        VersionRange::Range(low, high) => {
            let (low, low_inclusive) = match low {
                Version::Inclusive(version) => (Some(version.to_string()), true),
                Version::Exclusive(version) => (Some(version.to_string()), false),
                Version::Unbounded => (None, false),
            };

            let (high, high_inclusive) = match high {
                Version::Inclusive(version) => (Some(version.to_string()), true),
                Version::Exclusive(version) => (Some(version.to_string()), false),
                Version::Unbounded => (None, false),
            };

            (low, low_inclusive, high, high_inclusive)
        }
    };

    let low = low.map(|v| format!("'{v}'")).unwrap_or("null".to_string());
    let high = high.map(|v| format!("'{v}'")).unwrap_or("null".to_string());

    if let Some(result) = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM version_matches('{candidate}',
            (null, '{version_scheme}', {low}, {low_inclusive}, {high}, {high_inclusive})::version_range
        );
                "#,
            ),
        ))
        .await?
    {
        Ok(result.try_get_by_index::<bool>(0)?)
    } else {
        Ok(false)
    }
}
